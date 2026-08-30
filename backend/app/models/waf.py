from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class WafRule(Base):
    __tablename__ = "waf_rules"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    backend_id = Column(Integer, ForeignKey("backends.id"), nullable=True)
    name = Column(String, unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True)
    rule_set = Column(String, default="coraza")  # coraza, owasp-crs, custom, commercial
    rule_set_version = Column(String, nullable=True)
    rule_set_url = Column(String, nullable=True)
    rule_set_sha256 = Column(String, nullable=True)
    rule_set_auto_update = Column(Boolean, default=False)
    rule_set_update_interval_hours = Column(Integer, default=24)
    rule_set_last_updated_at = Column(DateTime, nullable=True)
    rule_set_last_error = Column(String, nullable=True)
    rule_set_plugins = Column(JSON, default=list)
    engine = Column(String, default="On")  # On, DetectionOnly, Off
    paranoia_level = Column(Integer, default=1)
    inbound_anomaly_threshold = Column(Integer, default=5)
    outbound_anomaly_threshold = Column(Integer, default=4)
    sec_rules = Column(Text, nullable=True)
    action = Column(String, default="block")  # block, allow, log, redirect, challenge
    redirect_url = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    captcha_valid_seconds = Column(Integer, default=3600)
    # Scope / conditions
    path_pattern = Column(String, nullable=True)
    http_methods = Column(String, nullable=True)
    content_types = Column(String, nullable=True)
    export_rule_ids = Column(Boolean, default=False)
    # Rate-based WAF
    rate_enabled = Column(Boolean, default=False)
    rate_events = Column(Integer, default=100)
    rate_window_seconds = Column(Integer, default=60)
    rate_key = Column(String, default="src")  # src, user_id, header, path
    rate_header = Column(String, nullable=True)
    rate_action = Column(String, default="block")  # block, challenge
    rate_duration_seconds = Column(Integer, default=0)  # 0 = no block duration (sliding window only)
    # Fail mode
    fail_open = Column(Boolean, default=False)
    siem_integration_id = Column(Integer, ForeignKey("waf_siem_integrations.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    listener = relationship("Listener")
    backend = relationship("Backend")
    siem_integration = relationship("WafSiemIntegration")


class WafException(Base):
    __tablename__ = "waf_exceptions"

    id = Column(Integer, primary_key=True, index=True)
    waf_rule_id = Column(Integer, ForeignKey("waf_rules.id"), nullable=True)
    name = Column(String, nullable=False)
    rule_id = Column(String, nullable=True)
    rule_tag = Column(String, nullable=True)
    rule_msg = Column(String, nullable=True)
    zone = Column(String, nullable=True)  # ARGS, HEADERS, etc
    variable = Column(String, nullable=True)
    matcher = Column(String, default="equals")  # equals, contains, regex, startsWith
    value = Column(String, nullable=True)
    description = Column(String, nullable=True)
    action = Column(String, default="remove")  # remove, allow, comment, update
    update_action = Column(String, nullable=True)  # pass, log, allow
    update_target = Column(String, nullable=True)  # variable to exclude
    condition_variable = Column(String, nullable=True)
    condition_operator = Column(String, default="equals")  # equals, regex, gt, lt
    condition_value = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class WafMetric(Base):
    __tablename__ = "waf_metrics"

    id = Column(Integer, primary_key=True, index=True)
    captured_at = Column(DateTime, default=utcnow, index=True)
    action = Column(String, nullable=False)
    rule_id = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    msg = Column(String, nullable=True)
    client = Column(String, nullable=True)
    country = Column(String, nullable=True)
    uri = Column(String, nullable=True)


class WafSiemIntegration(Base):
    __tablename__ = "waf_siem_integrations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    integration_type = Column(String, default="webhook")  # webhook, syslog, elastic
    target = Column(String, nullable=False)
    format = Column(String, default="json")  # json, syslog, cef
    auth_header = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class WafRuleVersion(Base):
    __tablename__ = "waf_rule_versions"

    id = Column(Integer, primary_key=True, index=True)
    waf_rule_id = Column(Integer, ForeignKey("waf_rules.id"), nullable=False)
    version = Column(String, nullable=False)
    snapshot = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    created_by = Column(String, nullable=True)

    rule = relationship("WafRule")


class ChallengeEvent(Base):
    __tablename__ = "challenge_events"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    rule_type = Column(String, nullable=False)  # "waf", "security", "rate_limit"
    rule_id = Column(Integer, nullable=True)
    rule_name = Column(String, nullable=True)
    listener_id = Column(Integer, nullable=True)
    client_ip = Column(String, nullable=True)
    event_type = Column(String, nullable=False)  # "issued", "solved", "failed"
    request_id = Column(String, nullable=True, index=True)  # HAProxy unique-id for cross-system correlation


__all__ = ['ChallengeEvent', 'WafException', 'WafMetric', 'WafRule', 'WafRuleVersion', 'WafSiemIntegration']
