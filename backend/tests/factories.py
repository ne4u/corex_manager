"""Test helpers for creating WAF-related database rows."""

from app.models.models import (
    Backend,
    CacheConfig,
    CacheRule,
    CspReport,
    FcgiApp,
    Listener,
    PageProtectPolicy,
    PageProtectScript,
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
)
from app.models.observability import CacheMetricSnapshot
from sqlalchemy.orm import Session


def make_backend(
    db: Session,
    name: str = "be",
    algorithm: str = "roundrobin",
    protocol: str = "http",
    mode: str = "http",
    fcgi_app_id: int | None = None,
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
    params: list | None = None,
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
    backend: Backend | None = None,
    name: str = "http_in",
    bind_address: str = "0.0.0.0",
    bind_port: int = 80,
    protocol: str = "http",
    mode: str = "http",
    enabled: bool = True,
    ssl_enabled: bool = False,
    options: dict | None = None,
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
        options=options or {},
    )
    db.add(listener)
    db.flush()
    return listener


def make_waf_rule(
    db: Session,
    name: str = "test-waf",
    listener_id: int | None = None,
    backend_id: int | None = None,
    enabled: bool = True,
    action: str = "block",
    redirect_url: str | None = None,
    status_code: int | None = 403,
    engine: str = "On",
    paranoia_level: int = 1,
    rule_set: str = "coraza",
    rule_set_url: str | None = None,
    rule_set_sha256: str | None = None,
    rule_set_auto_update: bool = False,
    rule_set_update_interval_hours: int = 24,
    path_pattern: str | None = None,
    http_methods: str | None = None,
    content_types: str | None = None,
    rate_enabled: bool = False,
    rate_events: int = 100,
    rate_window_seconds: int = 60,
    rate_action: str = "block",
    rate_key: str = "src",
    rate_header: str | None = None,
    rate_duration_seconds: int = 0,
    fail_open: bool = False,
    sec_rules: str | None = None,
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
        sec_rules=sec_rules,
        export_rule_ids=export_rule_ids,
    )
    db.add(rule)
    db.flush()
    return rule


def make_waf_exception(
    db: Session,
    waf_rule_id: int | None = None,
    name: str = "ex",
    rule_id: str | None = None,
    rule_tag: str | None = None,
    rule_msg: str | None = None,
    zone: str | None = None,
    variable: str | None = None,
    action: str = "remove",
    update_action: str | None = None,
    update_target: str | None = None,
    matcher: str | None = None,
    value: str | None = None,
    condition_variable: str | None = None,
    condition_operator: str | None = None,
    condition_value: str | None = None,
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


def make_rule_version(
    db: Session, waf_rule_id: int, version: str = "v1", snapshot: dict | None = None
) -> WafRuleVersion:
    v = WafRuleVersion(waf_rule_id=waf_rule_id, version=version, snapshot=snapshot or {})
    db.add(v)
    db.flush()
    return v


def make_waf_metric(
    db: Session,
    action: str = "deny",
    rule_id: str | None = None,
    severity: str | None = None,
    msg: str | None = None,
    client: str | None = None,
    country: str | None = None,
    uri: str | None = None,
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
    listener_id: int | None = None,
    name: str = "rl",
    limit_type: str = "waf",
    waf_event_threshold: int = 1,
    enabled: bool = True,
    events: int = 100,
    window_seconds: int = 60,
    duration_seconds: int = 0,
    response_code: int | None = None,
    action: str = "block",
    waf_block_duration: int | None = None,
    waf_window_seconds: int | None = None,
    log: bool = True,
    no_log: bool = False,
    match_status_code: int | None = None,
    rate_key: str = "src",
    rate_header: str | None = None,
    expression: str | None = None,
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
    listener_ids: list | None = None,
    log: bool = True,
    no_log: bool = False,
    status_code: int | None = None,
    redirect_url: str | None = None,
    redirect_code: int | None = None,
    error_page_id: int | None = None,
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
    listener_id: int | None = None,
    listener_ids: list | None = None,
    host_match: str | None = None,
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
    backend_id: int | None = None,
    backend_ids: list | None = None,
    header: str = "X-Forwarded-For",
    value: str = "%[src]",
    action: str = "override",
    condition: str | None = None,
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
    backend_ids: list | None = None,
    mode: str = "monitor",
    sample_rate_percent: int = 100,
    report_path: str = "/_csp-report",
    directives: dict | None = None,
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
    policy_id: int | None = None,
    client_ip: str | None = "1.2.3.4",
    document_uri: str | None = "https://example.com/page",
    violated_directive: str | None = "script-src",
    blocked_uri: str | None = "https://evil.example.com/script.js",
    backend_name: str | None = "be",
    listener_name: str | None = "http_in",
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
    domain: str | None = "cdn.example.com",
    hash_changed: bool = False,
    ignored: bool = False,
    content: str | None = None,
    last_hash: str | None = None,
    last_hash_at=None,
    notes: str | None = None,
    last_seen=None,
    hash_checked_at=None,
    source: str = "csp",
    fetch_method: str = "auto",
    last_fetch_method: str | None = None,
) -> PageProtectScript:
    s = PageProtectScript(
        url=url,
        resource_type=resource_type,
        domain=domain,
        hash_changed=hash_changed,
        ignored=ignored,
        content=content,
        last_hash=last_hash,
        last_hash_at=last_hash_at,
        notes=notes,
        last_seen=last_seen,
        hash_checked_at=hash_checked_at,
        source=source,
        fetch_method=fetch_method,
        last_fetch_method=last_fetch_method,
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
    haproxy_cache_condition: str | None = None,
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
) -> CacheRule:
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
    backend_id: int | None = None,
    backend_ids: list | None = None,
    transform_type: str = "replace",
    enabled: bool = True,
    priority: int = 0,
    content_types: str | None = None,
    max_body_size: int = 1048576,
    find_regex: str | None = None,
    replace_string: str | None = None,
    inject_string: str | None = None,
    inject_position: str | None = None,
    mask_mode: str | None = None,
    detector: str | None = None,
    token_mode: str | None = None,
    token_prefix: str | None = None,
    token_ttl: int | None = None,
    encrypt_key_env: str | None = None,
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
    haproxy_stats: dict | None = None,
    disk_cache_stats: dict | None = None,
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
