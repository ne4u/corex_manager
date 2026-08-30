import os
from typing import List, Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import (
    Listener,
    WafException,
    WafRule,
)
from . import coraza_watcher

settings = get_settings()


def _safe_token(value: Optional[str]) -> str:
    """Sanitize a value used as a Coraza config token."""
    if not isinstance(value, str):
        value = str(value) if value is not None else ""
    return value.replace("\r", "").replace("\n", " ").replace('"', "'").strip()


def _escape_pattern(value: str) -> str:
    """Escape double quotes and backslashes for a Coraza regex pattern token."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _scope_check_lines(primary: WafRule) -> List[str]:
    """Generate a skipAfter block if the rule has path/method/content type filters."""
    lines = []
    checks = []
    marker = "HAPROXY-WAF-SCOPE-END"

    path = _safe_token(primary.path_pattern)
    if path:
        pat = _escape_pattern(path)
        checks.append(f'SecRule REQUEST_URI "!@beginsWith {pat}" "id:990100,phase:1,pass,nolog,skipAfter:{marker}"')
    methods = _safe_token(primary.http_methods)
    if methods:
        # Coraza @within expects a comma-separated list.
        mlist = ",".join(m.strip() for m in methods.split(",") if m.strip())
        checks.append(f'SecRule REQUEST_METHOD "!@within {mlist}" "id:990101,phase:1,pass,nolog,skipAfter:{marker}"')
    ctypes = _safe_token(primary.content_types)
    if ctypes:
        ctypes_list = [c.strip() for c in ctypes.split(",") if c.strip()]
        # Chain the content-type rules so the skip only happens when none of the
        # allowed prefixes match.
        for i, ct in enumerate(ctypes_list):
            rule_id = 990102 + i
            is_last = i == len(ctypes_list) - 1
            if is_last:
                checks.append(f'SecRule REQUEST_HEADERS:Content-Type "!@beginsWith {ct}" "id:{rule_id},phase:1,pass,nolog,skipAfter:{marker}"')
            else:
                checks.append(f'SecRule REQUEST_HEADERS:Content-Type "!@beginsWith {ct}" "id:{rule_id},phase:1,pass,nolog,chain"')

    if checks:
        lines.append("# Scope / context filters")
        lines.extend(checks)
        lines.append(f"SecMarker {marker}")
    return lines


_OP_MAP = {
    "equals": "@streq",
    "contains": "@contains",
    "regex": "@rx",
    "startsWith": "@beginsWith",
    "gt": "@gt",
    "lt": "@lt",
}


def _coraza_op(op: Optional[str]) -> str:
    """Map a matcher/condition operator name to a Coraza @operator."""
    return _OP_MAP.get(_safe_token(op), "@streq")


def _exception_ctl_action(action: str, rule_id: str, rule_tag: str, rule_msg: str, target: str) -> Optional[str]:
    """Build the ctl: action string for a conditional exception."""
    if action == "remove":
        if rule_id:
            return f"ctl:ruleRemoveById={rule_id}"
        if rule_tag:
            return f"ctl:ruleRemoveByTag={rule_tag}"
        if rule_msg:
            return f"ctl:ruleRemoveByMsg={rule_msg}"
        # No specific rule target: disable the entire rule engine for the
        # remainder of this transaction. This is the "bypass all rules" case
        # (e.g. skip the WAF entirely when REQUEST_URI contains a given path).
        # Without this, a "remove" exception with no rule_id/tag/msg was
        # silently dropped and never reached the generated config.
        return "ctl:ruleEngine=Off"
    elif action == "allow" and target:
        if rule_id:
            return f"ctl:ruleRemoveTargetById={rule_id};{target}"
        if rule_tag:
            return f"ctl:ruleRemoveTargetByTag={rule_tag};{target}"
        if rule_msg:
            return f"ctl:ruleRemoveTargetByMsg={rule_msg};{target}"
    elif action == "comment":
        if rule_id:
            return f"ctl:ruleRemoveById={rule_id}"
        if rule_tag:
            return f"ctl:ruleRemoveByTag={rule_tag}"
        if rule_msg:
            return f"ctl:ruleRemoveByMsg={rule_msg}"
    return None


def _exception_lines(exceptions: List[WafException]) -> tuple[List[str], List[str]]:
    """Split exception directives into conditional and unconditional groups.

    Returns ``(conditional_lines, unconditional_lines)``.

    **Conditional** exceptions use runtime ``ctl:ruleRemove*`` actions inside a
    ``SecRule``. These only affect rules evaluated *after* the ctl action fires
    in the current transaction, so they **must** be emitted before the CRS
    ``Include`` directives. Otherwise the CRS rules have already run (and the
    blocking meta-rules like 949110/959100 have already denied the request) by
    the time the ctl takes effect.

    **Unconditional** exceptions use config-time directives
    (``SecRuleRemoveById``, ``SecRuleUpdateTargetByTag``, etc.) that remove or
    alter rules regardless of when they execute, so they can stay after the
    includes (matching the CRS convention where ``crs-setup.conf`` removals
    appear before the rules, and post-include removals also work).
    """
    conditional: List[str] = []
    unconditional: List[str] = []

    for ex in exceptions:
        action = _safe_token(ex.action) or "remove"
        rule_id = _safe_token(ex.rule_id)
        rule_tag = _safe_token(ex.rule_tag)
        rule_msg = _safe_token(ex.rule_msg)
        zone = _safe_token(ex.zone)
        variable = _safe_token(ex.variable)
        update_action = _safe_token(ex.update_action)
        update_target = _safe_token(ex.update_target)
        matcher = _safe_token(ex.matcher)
        value = _safe_token(ex.value)
        cond_var = _safe_token(ex.condition_variable)
        cond_op = _safe_token(ex.condition_operator)
        cond_val = _safe_token(ex.condition_value)

        target = f"{zone}:{variable}" if zone and variable else (variable or zone)
        has_condition = bool(cond_var and cond_val)
        has_matcher = bool(matcher and value and target and action == "allow")

        # --- Conditional exceptions (condition_variable + condition_value) ---
        # Use ctl:ruleRemoveById / ctl:ruleRemoveTargetById as SecRule actions
        # so the exception only applies when the condition matches.
        if has_condition:
            ctl = _exception_ctl_action(action, rule_id, rule_tag, rule_msg, target)
            if ctl is None:
                continue
            cond_operator = _coraza_op(cond_op)
            cond_pattern = _escape_pattern(cond_val)
            ex_id = 990200 + ex.id
            if has_matcher:
                # Chain condition + matcher: only exclude when both match
                matcher_op = _coraza_op(matcher)
                matcher_pattern = _escape_pattern(value)
                conditional.append(
                    f'SecRule {cond_var} "{cond_operator} {cond_pattern}" '
                    f'"id:{ex_id},phase:1,pass,nolog,chain"'
                )
                conditional.append(
                    f'    SecRule {target} "{matcher_op} {matcher_pattern}" "{ctl}"'
                )
            else:
                conditional.append(
                    f'SecRule {cond_var} "{cond_operator} {cond_pattern}" '
                    f'"id:{ex_id},phase:1,pass,nolog,{ctl}"'
                )
            if action == "comment":
                conditional.append(f"# Exception '{_safe_token(ex.name)}': conditional {action} for {rule_id or rule_tag or rule_msg}")
            continue

        # --- Matcher-only exceptions (matcher + value, no condition) ---
        # Exclude a variable from a rule only when the variable content matches.
        if has_matcher and not has_condition:
            matcher_op = _coraza_op(matcher)
            matcher_pattern = _escape_pattern(value)
            ex_id = 990200 + ex.id
            ctl = _exception_ctl_action("allow", rule_id, rule_tag, rule_msg, target)
            if ctl:
                conditional.append(
                    f'SecRule {target} "{matcher_op} {matcher_pattern}" '
                    f'"id:{ex_id},phase:1,pass,nolog,{ctl}"'
                )
            continue

        # --- Unconditional exceptions (no condition, no matcher) ---
        if rule_id:
            if action == "remove":
                unconditional.append(f"SecRuleRemoveById {rule_id}")
            elif action == "comment":
                unconditional.append(f"# Exception '{_safe_token(ex.name)}': disabled rule {rule_id}")
                unconditional.append(f"SecRuleRemoveById {rule_id}")
            elif action == "allow" and (variable or zone):
                unconditional.append(f"SecRuleUpdateTargetById {rule_id} !{target}")
            elif action == "update" and update_target and update_action:
                unconditional.append(f"SecRuleUpdateActionById {rule_id} \"{update_action}\"")
                unconditional.append(f"SecRuleUpdateTargetById {rule_id} !{update_target}")

        if rule_tag:
            if action == "remove":
                unconditional.append(f"SecRuleRemoveByTag {rule_tag}")
            elif action == "allow" and (variable or zone):
                unconditional.append(f"SecRuleUpdateTargetByTag {rule_tag} !{target}")
            elif action == "update" and update_target and update_action:
                unconditional.append(f"SecRuleUpdateActionByTag {rule_tag} \"{update_action}\"")
                unconditional.append(f"SecRuleUpdateTargetByTag {rule_tag} !{update_target}")

        if rule_msg:
            if action == "remove":
                unconditional.append(f"SecRuleRemoveByMsg {rule_msg}")
            elif action == "allow" and (variable or zone):
                unconditional.append(f"SecRuleUpdateTargetByMsg {rule_msg} !{target}")
            elif action == "update" and update_target and update_action:
                unconditional.append(f"SecRuleUpdateActionByMsg {rule_msg} \"{update_action}\"")
                unconditional.append(f"SecRuleUpdateTargetByMsg {rule_msg} !{update_target}")

    return conditional, unconditional


def _rate_limit_lines(primary: WafRule) -> List[str]:
    """Generate Coraza rate-limiting directives using the IP collection.

    NOTE: Coraza's setvar action only supports the TX collection, so
    persistent IP-based counting inside Coraza is not currently supported.
    Rate limiting is enforced in HAProxy (stick-tables / sc-inc-gpc0).
    """
    # Returning an empty list avoids the invalid "setvar:ip.*" directives that
    # would cause: "invalid arguments, expected collection TX".
    return []


def _app_directives(
    db: Session,
    rules: List[WafRule],
    exceptions: List[WafException],
) -> str:
    """Build Coraza directives for one application as a multi-line string."""
    if not rules:
        return "SecRuleEngine Off\n"

    # Use the first enabled rule for the base engine / paranoia / thresholds.
    # If multiple rules are bound to the same listener, their custom rules and
    # exceptions are merged, but the tuning parameters come from the first.
    primary = rules[0]
    # The WAF engine mode is independent of the HAProxy response action.
    # Even "log" rules need Coraza to interrupt with a deny verdict so that
    # HAProxy can count the event for rate limiting; the response action just
    # decides what HAProxy does with that verdict.
    engine = _safe_token(primary.engine) or "On"
    paranoia = max(1, min(4, int(primary.paranoia_level or 1)))
    inbound = int(primary.inbound_anomaly_threshold or 5)
    outbound = int(primary.outbound_anomaly_threshold or 4)

    lines = [
        f"SecAction \"id:900001,phase:1,nolog,pass,setvar:tx.paranoia_level={paranoia}\"",
        f"SecAction \"id:900002,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold={inbound}\"",
        f"SecAction \"id:900003,phase:1,nolog,pass,setvar:tx.outbound_anomaly_score_threshold={outbound}\"",
    ]

    # Rule set version / plugin metadata
    for r in rules:
        if r.rule_set_version:
            lines.append(f"# Rule set {r.rule_set} version {r.rule_set_version}")
        plugins = r.rule_set_plugins or []
        if plugins:
            lines.append(f"# Plugins: {','.join(str(p) for p in plugins)}")

    # Scope checks must appear before the rules they should skip
    scope = _scope_check_lines(primary)
    if scope:
        lines.extend(scope)

    rate = _rate_limit_lines(primary)
    if rate:
        lines.extend(rate)

    # Conditional/matcher exceptions use runtime ctl: actions that only affect
    # rules evaluated AFTER them in the transaction, so they must appear before
    # the CRS Include directives. Otherwise CRS rules (and the blocking
    # meta-rules 949110/959100) have already fired by the time the ctl takes
    # effect, and the exception silently does nothing.
    conditional_exceptions, unconditional_exceptions = _exception_lines(exceptions)
    if conditional_exceptions:
        lines.append("# Conditional exceptions (must precede rule set includes)")
        lines.extend(conditional_exceptions)

    # Base includes for bundled rule sets in the official main image.
    # If a CRS version has been downloaded from GitHub, use filesystem includes
    # from the shared volume. Otherwise, fall back to the embedded @owasp_crs.
    rule_sets = {r.rule_set for r in rules}
    if rule_sets & {"coraza", "owasp-crs", "crs"}:
        from .crs_downloader import get_active_crs_version, _crs_dir, _coraza_crs_path
        active_crs = get_active_crs_version(db)
        if active_crs and os.path.exists(_crs_dir(active_crs)):
            crs_path = _coraza_crs_path(active_crs)
            lines.append("Include @coraza.conf-recommended")
            lines.append(f"Include {crs_path}/crs-setup.conf.example")
            lines.append(f"Include {crs_path}/rules/*.conf")
        else:
            lines.extend([
                "Include @coraza.conf-recommended",
                "Include @crs-setup.conf.example",
                "Include @owasp_crs/*.conf",
            ])

    # Remote rule sets: Include downloaded .conf files from the shared volume.
    from .rule_set_downloader import _coraza_include_path, _rule_file_path
    for r in rules:
        if r.rule_set == "remote" and r.rule_set_url:
            abs_path = _rule_file_path(r.name)
            if os.path.exists(abs_path):
                coraza_path = _coraza_include_path(r.name)
                lines.append(f"Include {coraza_path}")
            else:
                lines.append(f"# Remote rule set '{r.name}' not yet downloaded from {r.rule_set_url}")

    # Unconditional exceptions (config-time SecRuleRemove*/SecRuleUpdate*
    # directives) are emitted after the includes. These work regardless of
    # position because they modify the rule set at config load time.
    if unconditional_exceptions:
        lines.append("# Unconditional exceptions")
        lines.extend(unconditional_exceptions)

    # Custom rules from all enabled rules
    for r in rules:
        if r.sec_rules:
            for raw_line in r.sec_rules.splitlines():
                line = _safe_token(raw_line)
                if line:
                    lines.append(line)

    # Set the rule engine last so it overrides the DetectionOnly default in
    # the bundled coraza.conf. CRS ships with crs-setup.conf which uses pass
    # by default; the scoring meta-rules (e.g. 949110) use explicit deny so
    # they will block once the engine is On.
    lines.append(f"SecRuleEngine {engine}")

    return "\n".join(lines) + "\n"


def _app_block(name: str, directives: str) -> str:
    return f"""    - name: {name}
      directives: |
{_indent(directives, width=8)}      log_level: info
      log_file: {settings.CORAZA_SPOA_LOG_PATH}
      log_format: json
      response_check: false
      transaction_ttl_ms: 60000
"""


def _indent(text: str, width: int = 4) -> str:
    pad = " " * width
    return "".join(f"{pad}{line}\n" for line in text.splitlines())


def _enabled_rules(rules: List[WafRule]) -> List[WafRule]:
    return [r for r in rules if r.enabled]


def _listener_default_backend_id(db: Session, listener_id: Optional[int]) -> Optional[int]:
    if listener_id is None:
        return None
    listener = db.get(Listener, listener_id)
    return listener.default_backend_id if listener else None


def _rules_for_listener(db: Session, listener_id: Optional[int]) -> List[WafRule]:
    all_rules = db.query(WafRule).all()
    enabled = _enabled_rules(all_rules)
    default_backend_id = _listener_default_backend_id(db, listener_id)

    # Rules tied to this listener (no backend, or matching default backend)
    specific = [
        r for r in enabled
        if r.listener_id == listener_id
        and (r.backend_id is None or r.backend_id == default_backend_id)
    ]
    if specific:
        # Include this listener's specific rules plus any global rules
        global_rules = [
            r for r in enabled
            if r.listener_id is None
            and (r.backend_id is None or r.backend_id == default_backend_id)
        ]
        return specific + global_rules

    # Fallback to global rules matching the default backend
    return [
        r for r in enabled
        if r.listener_id is None
        and (r.backend_id is None or r.backend_id == default_backend_id)
    ]


def _exceptions_for_rules(db: Session, rules: List[WafRule]) -> List[WafException]:
    rule_ids = {r.id for r in rules}
    # Global exceptions (waf_rule_id is None) apply to every app block, matching
    # the nullable FK and the UI's "Global" option. Without this, a global
    # exception is silently dropped and never reaches the generated config, so
    # the on-disk file doesn't change and the "unapplied changes" banner never
    # appears after creating one.
    return [
        e for e in db.query(WafException).all()
        if e.waf_rule_id is None or e.waf_rule_id in rule_ids
    ]


def rules_for_listener(db: Session, listener_id: Optional[int]) -> List[WafRule]:
    """Return all enabled WAF rules that apply to a listener."""
    return _rules_for_listener(db, listener_id)


def has_waf_for_listener(db: Session, listener_id: int) -> bool:
    """Return True when at least one enabled WAF rule matches the listener."""
    return bool(rules_for_listener(db, listener_id))


def generate_coraza_spoa_config(db: Session) -> str:
    """Generate a Coraza SPOA YAML with one app per listener + a global fallback."""
    listeners = db.query(Listener).all()
    applications = []

    # One app per listener that has any matching enabled WAF rule.  This covers
    # listener-specific rules as well as global rules that are scoped to this
    # listener's default backend.
    seen = set()
    for listener in listeners:
        if not listener.enabled:
            continue
        rules = _rules_for_listener(db, listener.id)
        if not rules:
            continue
        if listener.id in seen:
            continue
        seen.add(listener.id)
        exceptions = _exceptions_for_rules(db, rules)
        app_name = f"haproxy-waf-listener-{listener.id}"
        applications.append(
            _app_block(
                app_name,
                _app_directives(db, rules, exceptions),
            )
        )

    # Global application for backend-agnostic rules with no listener.
    # These only apply when no listener-specific app is selected.
    global_rules = _rules_for_listener(db, None)
    if global_rules:
        global_exceptions = _exceptions_for_rules(db, global_rules)
        applications.append(
            _app_block(
                "haproxy-waf-global",
                _app_directives(db, global_rules, global_exceptions),
            )
        )

    # If no rules exist, still emit a disabled global app so Coraza starts cleanly
    if not applications:
        applications.append(
            _app_block("haproxy-waf", "SecRuleEngine Off\n")
        )

    # The default application must be one of the defined apps.
    default_app = "haproxy-waf"
    if global_rules:
        default_app = "haproxy-waf-global"
    elif applications:
        # Extract the first app name from the first _app_block YAML
        first_app = applications[0].strip().splitlines()[0]
        if first_app.startswith("- name:"):
            default_app = first_app.split(":", 1)[1].strip()

    return f"""# Coraza SPOA configuration
# Generated by coreX Manager - do not edit manually
bind: 0.0.0.0:{settings.CORAZA_SPOA_PORT}

log_level: info
log_file: {settings.CORAZA_SPOA_LOG_PATH}
log_format: json

default_application: {default_app}

applications:
{''.join(applications)}"""


def coraza_app_for_listener(listener_id: Optional[int], db: Session) -> str:
    """Return the Coraza application name to use for a given listener."""
    if listener_id is not None and rules_for_listener(db, listener_id):
        return f"haproxy-waf-listener-{listener_id}"
    if rules_for_listener(db, None):
        return "haproxy-waf-global"
    return settings.CORAZA_SPOA_APP


def write_coraza_spoa_config(db: Session, restart: bool = True) -> str:
    """Write the generated Coraza SPOA config to disk.

    The SPOA container is only restarted when the generated config differs from
    what is already on disk, so repeated calls (e.g. health polling) cannot put
    the container into a restart loop.
    """
    config = generate_coraza_spoa_config(db)
    path = os.path.abspath(settings.CORAZA_SPOA_CONFIG_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    previous = None
    try:
        with open(path, "r") as f:
            previous = f.read()
    except FileNotFoundError:
        pass

    changed = previous != config
    if changed:
        with open(path, "w") as f:
            f.write(config)

    if restart and changed:
        coraza_watcher.restart_coraza_spoa()
    return config
