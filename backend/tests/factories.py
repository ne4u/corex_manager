"""Test helpers for creating WAF-related database rows."""
from typing import Optional

from sqlalchemy.orm import Session

from app.models.models import (
    Backend,
    FcgiApp,
    Listener,
    RateLimit,
    RequestHeader,
    ResponseTransform,
    Rewrite,
    SecurityRule,
    Server,
    WafException,
    WafMetric,
    WafRule,
    WafRuleVersion,
    WafSiemIntegration,
    PageProtectPolicy,
    CspReport,
    PageProtectScript,
    CacheConfig,
    CacheRule,
)
from app.models.observability import CacheMetricSnapshot


def make_backend(
    db: Session,
    name: str = "be",
    algorithm: str = "roundrobin",
    protocol: str = "http",
    mode: str = "http",
    fcgi_app_id: Optional[int] = None,
) -> Backend:
    backend = Backend(
        name=name,
        algorithm=algorithm,
        protocol=protocol,
        mode=mode,
        fcgi_app_id=fcgi_app_id,
    )
    db.add(backend)
    db.flush()
    return backend


def make_fcgi_app(
    db: Session,
    name: str = "fcgi",
    docroot: str = "/var/www/html",
    index: str = "index.php",
    keep_conn: bool = True,
    params: Optional[list] = None,
) -> FcgiApp:
    app = FcgiApp(
        name=name,
        docroot=docroot,
        index=index,
        keep_conn=keep_conn,
        params=params or [],
    )
    db.add(app)
    db.flush()
    return app


def make_server(db: Session, backend_id: int, name: str = "srv1", address: str = "10.0.0.1", port: int = 80) -> Server:
    server = Server(backend_id=backend_id, name=name, address=address, port=port)
    db.add(server)
    db.flush()
    return server


def make_listener(
    db: Session,
    backend: Optional[Backend] = None,
    name: str = "http_in",
    bind_address: str = "0.0.0.0",
    bind_port: int = 80,
    protocol: str = "http",
    mode: str = "http",
    enabled: bool = True,
    ssl_enabled: bool = False,
) -> Listener:
    listener = Listener(
        name=name,
        bind_address=bind_address,
        bind_port=bind_port,
        protocol=protocol,
        mode=mode,
        default_backend_id=backend.id if backend else None,
        enabled=enabled,
        ssl_enabled=ssl_enabled,
    )
    db.add(listener)
    db.flush()
    return listener


def make_waf_rule(
    db: Session,
    name: str = "test-waf",
    listener_id: Optional[int] = None,
    backend_id: Optional[int] = None,
    enabled: bool = True,
    action: str = "block",
    redirect_url: Optional[str] = None,
    status_code: Optional[int] = 403,
    engine: str = "On",
    paranoia_level: int = 1,
    rule_set: str = "coraza",
    rule_set_url: Optional[str] = None,
    rule_set_sha256: Optional[str] = None,
    rule_set_auto_update: bool = False,
    rule_set_update_interval_hours: int = 24,
    path_pattern: Optional[str] = None,
    http_methods: Optional[str] = None,
    content_types: Optional[str] = None,
    rate_enabled: bool = False,
    rate_events: int = 100,
    rate_window_seconds: int = 60,
    rate_action: str = "block",
    rate_key: str = "src",
    rate_header: Optional[str] = None,
    rate_duration_seconds: int = 0,
    fail_open: bool = False,
    siem_integration_id: Optional[int] = None,
    sec_rules: Optional[str] = None,
    export_rule_ids: bool = False,
) -> WafRule:
    rule = WafRule(
        name=name,
        listener_id=listener_id,
        backend_id=backend_id,
        enabled=enabled,
        action=action,
        redirect_url=redirect_url,
        status_code=status_code,
        engine=engine,
        paranoia_level=paranoia_level,
        rule_set=rule_set,
        rule_set_url=rule_set_url,
        rule_set_sha256=rule_set_sha256,
        rule_set_auto_update=rule_set_auto_update,
        rule_set_update_interval_hours=rule_set_update_interval_hours,
        path_pattern=path_pattern,
        http_methods=http_methods,
        content_types=content_types,
        rate_enabled=rate_enabled,
        rate_events=rate_events,
        rate_window_seconds=rate_window_seconds,
        rate_action=rate_action,
        rate_key=rate_key,
        rate_header=rate_header,
        rate_duration_seconds=rate_duration_seconds,
        fail_open=fail_open,
        siem_integration_id=siem_integration_id,
        sec_rules=sec_rules,
        export_rule_ids=export_rule_ids,
    )
    db.add(rule)
    db.flush()
    return rule


def make_waf_exception(
    db: Session,
    waf_rule_id: Optional[int] = None,
    name: str = "ex",
    rule_id: Optional[str] = None,
    rule_tag: Optional[str] = None,
    rule_msg: Optional[str] = None,
    zone: Optional[str] = None,
    variable: Optional[str] = None,
    action: str = "remove",
    update_action: Optional[str] = None,
    update_target: Optional[str] = None,
    matcher: Optional[str] = None,
    value: Optional[str] = None,
    condition_variable: Optional[str] = None,
    condition_operator: Optional[str] = None,
    condition_value: Optional[str] = None,
) -> WafException:
    ex = WafException(
        waf_rule_id=waf_rule_id,
        name=name,
        rule_id=rule_id,
        rule_tag=rule_tag,
        rule_msg=rule_msg,
        zone=zone,
        variable=variable,
        action=action,
        update_action=update_action,
        update_target=update_target,
        matcher=matcher,
        value=value,
        condition_variable=condition_variable,
        condition_operator=condition_operator,
        condition_value=condition_value,
    )
    db.add(ex)
    db.flush()
    return ex


def make_siem_integration(
    db: Session,
    name: str = "siem",
    integration_type: str = "webhook",
    target: str = "http://x",
    format: str = "json",
    enabled: bool = True,
) -> WafSiemIntegration:
    siem = WafSiemIntegration(
        name=name,
        integration_type=integration_type,
        target=target,
        format=format,
        enabled=enabled,
    )
    db.add(siem)
    db.flush()
    return siem


def make_rule_version(db: Session, waf_rule_id: int, version: str = "v1", snapshot: Optional[dict] = None) -> WafRuleVersion:
    v = WafRuleVersion(waf_rule_id=waf_rule_id, version=version, snapshot=snapshot or {})
    db.add(v)
    db.flush()
    return v


def make_waf_metric(
    db: Session,
    action: str = "deny",
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    msg: Optional[str] = None,
    client: Optional[str] = None,
    country: Optional[str] = None,
    uri: Optional[str] = None,
) -> WafMetric:
    m = WafMetric(
        action=action,
        rule_id=rule_id,
        severity=severity,
        msg=msg,
        client=client,
        country=country,
        uri=uri,
    )
    db.add(m)
    db.flush()
    return m


def make_rate_limit(
    db: Session,
    listener_id: Optional[int] = None,
    name: str = "rl",
    limit_type: str = "waf",
    waf_event_threshold: int = 1,
    enabled: bool = True,
    events: int = 100,
    window_seconds: int = 60,
    duration_seconds: int = 0,
    response_code: Optional[int] = None,
    action: str = "block",
    waf_block_duration: Optional[int] = None,
    waf_window_seconds: Optional[int] = None,
    log: bool = True,
    no_log: bool = False,
    match_status_code: Optional[int] = None,
    rate_key: str = "src",
    rate_header: Optional[str] = None,
    expression: Optional[str] = None,
) -> RateLimit:
    rl = RateLimit(
        listener_id=listener_id,
        name=name,
        limit_type=limit_type,
        waf_event_threshold=waf_event_threshold,
        enabled=enabled,
        events=events,
        window_seconds=window_seconds,
        duration_seconds=duration_seconds,
        response_code=response_code,
        action=action,
        waf_block_duration=waf_block_duration,
        waf_window_seconds=waf_window_seconds,
        log=log,
        no_log=no_log,
        match_status_code=match_status_code,
        rate_key=rate_key,
        rate_header=rate_header,
        expression=expression,
    )
    db.add(rl)
    db.flush()
    return rl


def make_security_rule(
    db: Session,
    name: str = "sec-rule",
    expression: str = 'http.host = "example.com"',
    action: str = "block",
    enabled: bool = True,
    priority: int = 0,
    listener_ids: Optional[list] = None,
    log: bool = True,
    no_log: bool = False,
    status_code: Optional[int] = None,
    redirect_url: Optional[str] = None,
    redirect_code: Optional[int] = None,
    error_page_id: Optional[int] = None,
) -> SecurityRule:
    rule = SecurityRule(
        name=name,
        expression=expression,
        action=action,
        enabled=enabled,
        priority=priority,
        listener_ids=listener_ids or [],
        log=log,
        no_log=no_log,
        status_code=status_code,
        redirect_url=redirect_url,
        redirect_code=redirect_code,
        error_page_id=error_page_id,
    )
    db.add(rule)
    db.flush()
    return rule


def make_rewrite(
    db: Session,
    name: str = "rw",
    listener_id: Optional[int] = None,
    listener_ids: Optional[list] = None,
    host_match: Optional[str] = None,
    source_regex: str = "^/",
    target: str = "/prefix%[path]",
    type: str = "path",
    priority: int = 0,
) -> Rewrite:
    rewrite = Rewrite(
        name=name,
        listener_id=listener_id,
        listener_ids=listener_ids or [],
        host_match=host_match,
        source_regex=source_regex,
        target=target,
        type=type,
        priority=priority,
    )
    db.add(rewrite)
    db.flush()
    return rewrite


def make_request_header(
    db: Session,
    name: str = "rh",
    backend_id: Optional[int] = None,
    backend_ids: Optional[list] = None,
    header: str = "X-Forwarded-For",
    value: str = "%[src]",
    action: str = "override",
    condition: Optional[str] = None,
) -> RequestHeader:
    rh = RequestHeader(
        name=name,
        backend_id=backend_id,
        backend_ids=backend_ids or [],
        header=header,
        value=value,
        action=action,
        condition=condition,
    )
    db.add(rh)
    db.flush()
    return rh


def make_page_protect_policy(
    db: Session,
    name: str = "pp-policy",
    enabled: bool = True,
    backend_ids: Optional[list] = None,
    mode: str = "monitor",
    sample_rate_percent: int = 100,
    report_path: str = "/_csp-report",
    directives: Optional[dict] = None,
) -> PageProtectPolicy:
    p = PageProtectPolicy(
        name=name,
        enabled=enabled,
        backend_ids=backend_ids or [],
        mode=mode,
        sample_rate_percent=sample_rate_percent,
        report_path=report_path,
        directives=directives or {"default-src": ["'self'"]},
    )
    db.add(p)
    db.flush()
    return p


def make_csp_report(
    db: Session,
    policy_id: Optional[int] = None,
    client_ip: Optional[str] = "1.2.3.4",
    document_uri: Optional[str] = "https://example.com/page",
    violated_directive: Optional[str] = "script-src",
    blocked_uri: Optional[str] = "https://evil.example.com/script.js",
    backend_name: Optional[str] = "be",
    listener_name: Optional[str] = "http_in",
    report_type: str = "csp",
) -> CspReport:
    r = CspReport(
        policy_id=policy_id,
        client_ip=client_ip,
        document_uri=document_uri,
        violated_directive=violated_directive,
        blocked_uri=blocked_uri,
        backend_name=backend_name,
        listener_name=listener_name,
        report_type=report_type,
    )
    db.add(r)
    db.flush()
    return r


def make_page_protect_script(
    db: Session,
    url: str = "https://cdn.example.com/script.js",
    resource_type: str = "script",
    domain: Optional[str] = "cdn.example.com",
    hash_changed: bool = False,
    last_hash: Optional[str] = None,
    last_hash_at=None,
    notes: Optional[str] = None,
    last_seen=None,
    hash_checked_at=None,
    source: str = "csp",
) -> PageProtectScript:
    s = PageProtectScript(
        url=url,
        resource_type=resource_type,
        domain=domain,
        hash_changed=hash_changed,
        last_hash=last_hash,
        last_hash_at=last_hash_at,
        notes=notes,
        last_seen=last_seen,
        hash_checked_at=hash_checked_at,
        source=source,
    )
    db.add(s)
    db.flush()
    return s


def make_cache_config(
    db: Session,
    backend_id: int,
    haproxy_enabled: bool = False,
    haproxy_total_max_size: int = 100,
    haproxy_max_object_size: int = 1000000,
    haproxy_max_age: int = 300,
    haproxy_process_vary: bool = True,
    haproxy_max_secondary_entries: int = 10,
    haproxy_cache_condition: Optional[str] = None,
    haproxy_rfc7234_compliance: bool = False,
    disk_cache_enabled: bool = False,
    disk_cache_ttl: int = 120,
    disk_cache_grace: int = 600,
    disk_cache_purge_enabled: bool = True,
) -> CacheConfig:
    cc = CacheConfig(
        backend_id=backend_id,
        haproxy_enabled=haproxy_enabled,
        haproxy_total_max_size=haproxy_total_max_size,
        haproxy_max_object_size=haproxy_max_object_size,
        haproxy_max_age=haproxy_max_age,
        haproxy_process_vary=haproxy_process_vary,
        haproxy_max_secondary_entries=haproxy_max_secondary_entries,
        haproxy_cache_condition=haproxy_cache_condition,
        haproxy_rfc7234_compliance=haproxy_rfc7234_compliance,
        disk_cache_enabled=disk_cache_enabled,
        disk_cache_ttl=disk_cache_ttl,
        disk_cache_grace=disk_cache_grace,
        disk_cache_purge_enabled=disk_cache_purge_enabled,
    )
    db.add(cc)
    db.flush()
    return cc


def make_cache_rule(
    db,
    cache_config_id: int,
    match_type: str = "extension",
    pattern: str = "png",
    action: str = "cache",
    tier: str = "memory",  # Default to memory for test convenience
    enabled: bool = True,
    priority: int = 0,
) -> "CacheRule":
    rule = CacheRule(
        cache_config_id=cache_config_id,
        match_type=match_type,
        pattern=pattern,
        action=action,
        tier=tier,
        enabled=enabled,
        priority=priority,
    )
    db.add(rule)
    db.flush()
    return rule


def make_response_transform(
    db: Session,
    name: str = "rt",
    backend_id: Optional[int] = None,
    backend_ids: Optional[list] = None,
    transform_type: str = "replace",
    enabled: bool = True,
    priority: int = 0,
    content_types: Optional[str] = None,
    max_body_size: int = 1048576,
    find_regex: Optional[str] = None,
    replace_string: Optional[str] = None,
    inject_string: Optional[str] = None,
    inject_position: Optional[str] = None,
    mask_mode: Optional[str] = None,
    detector: Optional[str] = None,
    token_mode: Optional[str] = None,
    token_prefix: Optional[str] = None,
    token_ttl: Optional[int] = None,
    encrypt_key_env: Optional[str] = None,
    detokenize_query: bool = False,
) -> ResponseTransform:
    rt = ResponseTransform(
        name=name,
        backend_id=backend_id,
        backend_ids=backend_ids or [],
        transform_type=transform_type,
        enabled=enabled,
        priority=priority,
        content_types=content_types,
        max_body_size=max_body_size,
        find_regex=find_regex,
        replace_string=replace_string,
        inject_string=inject_string,
        inject_position=inject_position,
        mask_mode=mask_mode,
        detector=detector,
        token_mode=token_mode,
        token_prefix=token_prefix,
        token_ttl=token_ttl,
        encrypt_key_env=encrypt_key_env,
        detokenize_query=detokenize_query,
    )
    db.add(rt)
    db.flush()
    return rt


def make_cache_metric_snapshot(
    db: Session,
    backend_id: int,
    created_at,
    haproxy_stats: Optional[dict] = None,
    disk_cache_stats: Optional[dict] = None,
) -> CacheMetricSnapshot:
    """Insert a CacheMetricSnapshot row with an explicit timestamp.

    ``created_at`` should be a naive UTC datetime (matching how the sampler
    stores rows).
    """
    snap = CacheMetricSnapshot(
        created_at=created_at,
        backend_id=backend_id,
        haproxy_stats=haproxy_stats or {},
        disk_cache_stats=disk_cache_stats or {},
    )
    db.add(snap)
    db.flush()
    return snap
