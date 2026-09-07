"""Suggestion catalog for the WAF exception editor.

Aggregates the values a user is most likely to need when creating a WAF
exception — rule ids, tags, messages, exclusion zones, variables and
condition variables — from every source available on this deployment:

- ``waf_metrics``: rules that have actually fired (with hit counts).
- Rule-set files on disk: downloaded CRS versions (``CRS_DIR/<ver>/rules``),
  downloaded remote rule sets (``CUSTOM_RULES_DIR``) and each ``WafRule``'s
  ``sec_rules`` text. The bundled ``@owasp_crs`` set is compiled into the
  coraza-spoa binary, so it contributes nothing when no files exist.
- The raw coraza-spoa log tail: ``[tag "..."]`` / ``[id "..."]`` /
  ``[msg "..."]`` / ``[data "..."]`` bracket fields and JSON match objects.
- Existing ``waf_exceptions`` rows (values already in use).
- Curated static lists (zones, common condition variables, well-known CRS
  tags) so the editor still offers useful options on a fresh install.
"""
import glob
import json
import logging
import os
import re
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.valkey_client import cache
from ..models.models import WafException, WafMetric, WafRule

logger = logging.getLogger(__name__)

settings = get_settings()

# How many lines of the raw coraza-spoa log to scan for tags/data/ids.
LOG_SCAN_LINES = 2000
# Max bytes read per rule file (CRS rule files are ~100KB each).
RULE_FILE_MAX_BYTES = 2 * 1024 * 1024
# Caps on each suggestion list.
MAX_RULES = 500
MAX_TAGS = 200
MAX_MSGS = 200
MAX_VARIABLES = 200

# Coraza/ModSecurity collections that can be exclusion targets
# (SecRuleUpdateTargetById / ctl:ruleRemoveTargetBy*).
DEFAULT_ZONES: List[str] = [
    "ARGS",
    "ARGS_NAMES",
    "REQUEST_HEADERS",
    "REQUEST_HEADERS_NAMES",
    "REQUEST_COOKIES",
    "REQUEST_COOKIES_NAMES",
    "REQUEST_BODY",
    "REQUEST_FILENAME",
    "QUERY_STRING",
    "XML",
]

# Common SecRule variables used as condition targets in practice.
DEFAULT_CONDITION_VARIABLES: List[str] = [
    "REQUEST_URI",
    "REQUEST_FILENAME",
    "QUERY_STRING",
    "REQUEST_METHOD",
    "REMOTE_ADDR",
    "SERVER_NAME",
    "REQUEST_HEADERS:Host",
    "REQUEST_HEADERS:User-Agent",
    "REQUEST_HEADERS:Referer",
    "REQUEST_HEADERS:Content-Type",
    "REQUEST_HEADERS",
    "REQUEST_COOKIES",
    "ARGS",
    "ARGS_NAMES",
    "REQUEST_BODY",
]

# Well-known OWASP CRS tags so the tag picker is useful even before any rule
# has fired and before any rule set has been downloaded to disk.
DEFAULT_TAGS: List[str] = [
    "OWASP_CRS",
    "attack-disclosure",
    "attack-fixation",
    "attack-injection-generic",
    "attack-injection-php",
    "attack-lfi",
    "attack-protocol",
    "attack-rce",
    "attack-reputation-scanner",
    "attack-rfi",
    "attack-scanner",
    "attack-sqli",
    "attack-xss",
    "language-multi",
    "paranoia-level/1",
    "paranoia-level/2",
    "paranoia-level/3",
    "paranoia-level/4",
    "platform-multi",
]

_RULE_LINE_RE = re.compile(r"^\s*Sec(Rule|Action)\b")
_ID_RE = re.compile(r"\bid\s*:\s*['\"]?(\d+)")
_MSG_RE = re.compile(r"\bmsg\s*:\s*'([^']+)'|\bmsg\s*:\s*\"([^\"]+)\"")
_TAG_RE = re.compile(r"\btag\s*:\s*'([^']+)'|\btag\s*:\s*\"([^\"]+)\"")

_LOG_ID_RE = re.compile(r'\[id "(\d+)"\]')
_LOG_MSG_RE = re.compile(r'\[msg "([^"]+)"\]')
_LOG_TAG_RE = re.compile(r'\[tag "([^"]+)"\]')
_LOG_DATA_RE = re.compile(r'\[data "([^"]+)"\]')
# Coraza messages look like: 'Matched Data: <x> found within ARGS:foo: <y>'.
# Capture "ZONE:key" (or bare "ZONE") targets from "found within ..." text.
_WITHIN_RE = re.compile(r"within\s+([A-Z_]+(?::[^\s:.,'\"]+)?)")


def _first_group(match: Optional[re.Match]) -> Optional[str]:
    if not match:
        return None
    for g in match.groups():
        if g:
            return g
    return None


def _parse_rule_line(line: str) -> Optional[Dict[str, Any]]:
    """Extract {id, msg, tags} from a single SecRule/SecAction line."""
    if not _RULE_LINE_RE.match(line):
        return None
    id_match = _ID_RE.search(line)
    if not id_match:
        return None
    return {
        "id": id_match.group(1),
        "msg": _first_group(_MSG_RE.search(line)),
        "tags": [a or b for a, b in _TAG_RE.findall(line)],
    }


def _rule_texts(db: Session) -> List[str]:
    """Return the contents of every parseable rule source on disk / in the DB."""
    texts: List[str] = []

    # Downloaded CRS version (if the user fetched one via the CRS tab).
    try:
        from .crs_downloader import get_active_crs_version, _crs_dir

        active = get_active_crs_version(db)
        if active:
            rules_dir = os.path.join(_crs_dir(active), "rules")
            texts.extend(_read_rule_files(rules_dir))
    except Exception:
        pass

    # Downloaded remote rule sets (one .conf per WafRule name).
    texts.extend(_read_rule_files(os.path.abspath(settings.CUSTOM_RULES_DIR)))

    # Inline custom SecRules stored on each WafRule.
    try:
        for (txt,) in db.query(WafRule.sec_rules).filter(WafRule.sec_rules.isnot(None)):
            if txt:
                texts.append(txt)
    except Exception:
        pass

    return texts


def _read_rule_files(directory: str) -> List[str]:
    texts: List[str] = []
    if not os.path.isdir(directory):
        return texts
    for path in sorted(glob.glob(os.path.join(directory, "*.conf"))):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                texts.append(f.read(RULE_FILE_MAX_BYTES))
        except OSError:
            continue
    return texts


def _iter_match_objects(data: Dict[str, Any]):
    """Yield candidate match dicts from a parsed JSON log line."""
    match = data.get("match")
    if isinstance(match, dict):
        yield match
    if any(k in data for k in ("rule_id", "id", "tags", "data")):
        yield data
    for key in ("message", "msg"):
        nested = data.get(key)
        if isinstance(nested, dict):
            yield nested


def _collect_within(text: Optional[str], variables: Dict[Tuple[str, str], None]) -> None:
    """Extract 'ZONE:key' targets from 'found within ...' match data."""
    if not text:
        return
    for m in _WITHIN_RE.finditer(text):
        target = m.group(1)
        if ":" in target:
            zone, key = target.split(":", 1)
        else:
            zone, key = target, ""
        if zone and key is not None:
            variables[(zone, key)] = None


def _scan_log_tail() -> Tuple[set, set, set, Dict[Tuple[str, str], None]]:
    """Best-effort extraction of ids/tags/msgs/variable targets from the raw log."""
    ids: set = set()
    tags: set = set()
    msgs: set = set()
    variables: Dict[Tuple[str, str], None] = {}

    path = settings.CORAZA_SPOA_LOG_PATH
    if not os.path.exists(path):
        return ids, tags, msgs, variables
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = deque(f, maxlen=LOG_SCAN_LINES)
    except OSError:
        return ids, tags, msgs, variables

    for line in lines:
        ids.update(_LOG_ID_RE.findall(line))
        tags.update(_LOG_TAG_RE.findall(line))
        msgs.update(_LOG_MSG_RE.findall(line))
        for data_field in _LOG_DATA_RE.findall(line):
            _collect_within(data_field, variables)

        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        for match in _iter_match_objects(obj):
            for t in match.get("tags") or []:
                if t:
                    tags.add(str(t))
            rid = match.get("rule_id") or match.get("id")
            if rid is not None:
                ids.add(str(rid))
            msg = match.get("msg") or match.get("message")
            if isinstance(msg, str) and msg:
                msgs.add(msg)
            data_field = match.get("data")
            if isinstance(data_field, str):
                _collect_within(data_field, variables)

    return ids, tags, msgs, variables


@cache(ttl=60, key_prefix="waf")
def get_exception_options(db: Session) -> Dict[str, Any]:
    """Return the merged suggestion catalog for the WAF exception editor."""
    rules: Dict[str, Dict[str, Any]] = {}
    tags: set = set()
    msgs: Dict[str, Dict[str, Any]] = {}
    variables: Dict[Tuple[str, str], None] = {}
    zones_seen: set = set()
    cond_vars_seen: set = set()

    def add_rule(rid: str, msg: Optional[str] = None, rule_tags: Optional[List[str]] = None, hits: int = 0) -> None:
        entry = rules.setdefault(rid, {"id": rid, "msg": None, "tags": [], "hits": 0})
        if msg and not entry["msg"]:
            entry["msg"] = msg
        if rule_tags:
            merged = set(entry["tags"]) | set(rule_tags)
            entry["tags"] = sorted(merged)
        entry["hits"] += hits

    def add_msg(msg: str, rule_id: Optional[str] = None) -> None:
        entry = msgs.setdefault(msg, {"msg": msg, "rule_id": rule_id, "hits": 0})
        if rule_id and not entry["rule_id"]:
            entry["rule_id"] = rule_id

    # --- Observed WAF events ---
    try:
        rows = (
            db.query(WafMetric.rule_id, WafMetric.msg, func.count().label("hits"))
            .filter(WafMetric.rule_id.isnot(None), WafMetric.rule_id != "")
            .group_by(WafMetric.rule_id, WafMetric.msg)
            .order_by(func.count().desc())
            .limit(MAX_RULES)
            .all()
        )
        for rid, msg, hits in rows:
            add_rule(str(rid), msg=msg, hits=int(hits))
            if msg:
                msgs_entry = msgs.setdefault(msg, {"msg": msg, "rule_id": str(rid), "hits": 0})
                msgs_entry["hits"] += int(hits)
    except Exception:
        logger.exception("exception options: metrics scan failed")

    # --- Rule-set files and inline sec_rules ---
    for text in _rule_texts(db):
        for line in text.splitlines():
            parsed = _parse_rule_line(line)
            if not parsed:
                continue
            add_rule(parsed["id"], msg=parsed["msg"], rule_tags=parsed["tags"])
            tags.update(parsed["tags"])
            if parsed["msg"]:
                add_msg(parsed["msg"], rule_id=parsed["id"])

    # --- Raw coraza-spoa log tail ---
    log_ids, log_tags, log_msgs, log_vars = _scan_log_tail()
    for rid in log_ids:
        add_rule(rid)
    tags.update(log_tags)
    for msg in log_msgs:
        add_msg(msg)
    variables.update(log_vars)

    # --- Values already used by configured exceptions ---
    try:
        for ex in db.query(
            WafException.rule_id,
            WafException.rule_tag,
            WafException.rule_msg,
            WafException.zone,
            WafException.variable,
            WafException.condition_variable,
        ).all():
            for rid in _split_field(ex.rule_id):
                add_rule(rid)
            for tag in _split_field(ex.rule_tag):
                tags.add(tag)
            for msg in _split_field(ex.rule_msg, comma_only=True):
                add_msg(msg)
            for zone in _split_field(ex.zone):
                zones_seen.add(zone)
            if ex.zone and ex.variable:
                for zone in _split_field(ex.zone):
                    variables[(zone, ex.variable.strip())] = None
            if ex.condition_variable:
                cond_vars_seen.add(ex.condition_variable.strip())
    except Exception:
        logger.exception("exception options: exceptions scan failed")

    rule_list = sorted(rules.values(), key=lambda e: (-e["hits"], e["id"]))[:MAX_RULES]
    tag_list = sorted(tags | set(DEFAULT_TAGS), key=str.lower)[:MAX_TAGS]
    msg_list = sorted(msgs.values(), key=lambda e: (-e["hits"], e["msg"]))[:MAX_MSGS]
    var_list = [{"zone": z, "key": k} for z, k in sorted(variables)][:MAX_VARIABLES]

    zones = DEFAULT_ZONES + sorted(z for z in zones_seen if z not in DEFAULT_ZONES)
    cond_vars = DEFAULT_CONDITION_VARIABLES + sorted(v for v in cond_vars_seen if v not in DEFAULT_CONDITION_VARIABLES)

    return {
        "rules": rule_list,
        "tags": tag_list,
        "msgs": msg_list,
        "zones": zones,
        "variables": var_list,
        "condition_variables": cond_vars,
    }


def _split_field(value: Optional[str], comma_only: bool = False) -> List[str]:
    """Split a stored multi-value field (comma- or whitespace-separated)."""
    if not value:
        return []
    parts = value.split(",") if comma_only else re.split(r"[,\s]+", value)
    return [p.strip() for p in parts if p and p.strip()]
