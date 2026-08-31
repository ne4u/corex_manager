import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.models.models import WafMetric
from app.services import waf_metrics


def test_parse_line_json():
    line = json.dumps(
        {
            "action": "deny",
            "rule_id": "123",
            "severity": "CRITICAL",
            "msg": "XSS attempt",
            "client": "1.2.3.4",
            "uri": "/foo",
        }
    )
    parsed = waf_metrics._parse_line(line)
    assert parsed["action"] == "deny"
    assert parsed["rule_id"] == "123"
    assert parsed["severity"] == "CRITICAL"
    assert parsed["msg"] == "XSS attempt"
    assert parsed["client"] == "1.2.3.4"
    assert parsed["uri"] == "/foo"


def test_parse_line_json_alt_keys():
    line = json.dumps(
        {
            "id": "456",
            "action": "deny",
            "message": "Access denied.",
            "client_ip": "2.3.4.5",
            "path": "/bar",
            "severity": "HIGH",
        }
    )
    parsed = waf_metrics._parse_line(line)
    assert parsed["action"] == "deny"
    assert parsed["rule_id"] == "456"
    assert parsed["client"] == "2.3.4.5"
    assert parsed["uri"] == "/bar"


def test_parse_line_plain_text():
    line = '[client "1.2.3.4"] [id "123"] [severity "CRITICAL"] [msg "XSS"] Coraza: Access denied.'
    parsed = waf_metrics._parse_line(line)
    assert parsed["action"] == "deny"
    assert parsed["rule_id"] == "123"
    assert parsed["client"] == "1.2.3.4"


def test_parse_line_coraza_message_with_phase():
    line = json.dumps(
        {
            "level": "error",
            "time": "2026-08-03T23:11:09Z",
            "message": '[client "10.1.1.112"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 23) [file "@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "7443"] [id "949110"] [severity "emergency"] [uri "/?test=%3Cscript%3Ealert(1);%3C/script%3E"] [unique_id "TIIFNMXHKXEKXLYF"]',
        }
    )
    parsed = waf_metrics._parse_line(line)
    assert parsed["action"] == "deny"
    assert parsed["rule_id"] == "949110"
    assert parsed["severity"] == "emergency"
    assert parsed["client"] == "10.1.1.112"
    assert parsed["uri"] == "/?test=%3Cscript%3Ealert(1);%3C/script%3E"
    assert parsed["unique_id"] == "TIIFNMXHKXEKXLYF"
    assert "Inbound Anomaly Score Exceeded" in parsed["msg"]
    assert parsed["time"] == "2026-08-03T23:11:09Z"
    assert parsed["level"] == "error"


def test_parse_line_unknown_action():
    line = json.dumps({"message": "Coraza: Startup complete."})
    parsed = waf_metrics._parse_line(line)
    # Non-WAF log lines should have action=None (displayed as "-" in frontend)
    assert parsed["action"] is None
    # The message should be preserved in the msg field
    assert parsed["msg"] == "Coraza: Startup complete."


def test_parse_line_plain_log_line():
    """Startup/shutdown log lines should be parsed with level as severity and message in msg."""
    line = json.dumps({"level": "info", "time": "2026-08-04T19:44:25Z", "message": "Starting coraza-spoa"})
    parsed = waf_metrics._parse_line(line)
    assert parsed is not None
    assert parsed["action"] is None  # dash in frontend
    assert parsed["msg"] == "Starting coraza-spoa"
    assert parsed["severity"] == "info"  # level mapped to severity
    assert parsed["time"] == "2026-08-04T19:44:25Z"
    assert parsed["level"] == "info"


def test_parse_line_coraza_spoa_match_json():
    """coraza-spoa main logs a zerolog JSON line with a nested match object."""
    line = json.dumps({
        "level": "error",
        "time": "2026-08-05T12:00:00Z",
        "match": {
            "client": "192.168.1.50",
            "rule_id": 920420,
            "msg": "Request content type is not allowed by policy",
            "severity": "critical",
            "uri": "/",
            "unique_id": "ABCDEF123456",
            "disruptive": False,
        },
    })
    parsed = waf_metrics._parse_line(line)
    assert parsed["action"] == "pass"
    assert parsed["rule_id"] == "920420"
    assert parsed["severity"] == "critical"
    assert parsed["client"] == "192.168.1.50"
    assert parsed["uri"] == "/"
    assert parsed["unique_id"] == "ABCDEF123456"
    assert parsed["time"] == "2026-08-05T12:00:00Z"
    assert parsed["level"] == "error"


def test_parse_line_non_string_message_does_not_crash():
    """A log line with a non-string message must not raise."""
    line = json.dumps({"level": "info", "time": "2026-08-05T12:00:00Z", "message": ["noise"]})
    parsed = waf_metrics._parse_line(line)
    assert parsed is not None
    assert parsed["action"] is None
    assert parsed["msg"] == "noise"


def test_geo_country_with_reader():
    reader = MagicMock()
    reader.country.return_value.country.iso_code = "US"
    assert waf_metrics._geo_country("1.2.3.4", reader) == "US"


def test_geo_country_unknown_without_reader():
    assert waf_metrics._geo_country("1.2.3.4", None) == "unknown"


def test_geo_country_lookup_error():
    reader = MagicMock()
    reader.country.side_effect = ValueError("bad ip")
    assert waf_metrics._geo_country("not-an-ip", reader) == "unknown"


def test_sample_waf_metrics(db, temp_coraza_paths, monkeypatch):
    log_path = temp_coraza_paths["log"]
    lines = [
        json.dumps({"action": "deny", "rule_id": "1", "severity": "CRITICAL", "msg": "XSS", "client": "1.2.3.4", "uri": "/a"}),
        json.dumps({"action": "drop", "rule_id": "2", "severity": "HIGH", "msg": "SQLi", "client": "5.6.7.8", "uri": "/b"}),
        json.dumps({"message": "noise"}),
    ]
    with open(log_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    monkeypatch.setattr(waf_metrics, "_geo_country", lambda ip, reader: "US" if ip == "1.2.3.4" else "CA")
    monkeypatch.setattr(waf_metrics.settings, "GEOIP_DB_PATH", "/nonexistent.mmdb")

    waf_metrics.sample_waf_metrics()

    metrics = db.query(WafMetric).order_by(WafMetric.id).all()
    assert len(metrics) == 2
    assert metrics[0].action == "deny"
    assert metrics[0].rule_id == "1"
    assert metrics[0].country == "US"
    assert metrics[1].action == "drop"
    assert metrics[1].country == "CA"


def test_sample_waf_metrics_offset_and_truncate(db, temp_coraza_paths, monkeypatch):
    log_path = temp_coraza_paths["log"]
    offset_path = temp_coraza_paths["offset"]
    line1 = json.dumps({"action": "deny", "rule_id": "1", "severity": "CRITICAL", "msg": "XSS", "client": "1.2.3.4", "uri": "/a"})

    with open(log_path, "w") as f:
        f.write(line1 + "\n")

    # Simulate a previous full read
    with open(offset_path, "w") as f:
        f.write(str(len(line1) + 1))

    # Truncate file so offset is past EOF
    with open(log_path, "w") as f:
        f.write("")

    monkeypatch.setattr(waf_metrics, "_geo_country", lambda ip, reader: "US")
    monkeypatch.setattr(waf_metrics.settings, "GEOIP_DB_PATH", "/nonexistent.mmdb")

    waf_metrics.sample_waf_metrics()
    assert db.query(WafMetric).count() == 0
    assert Path(offset_path).read_text() == "0"


def test_get_waf_metrics_breakdowns(db):
    now = datetime.now(timezone.utc)
    for i, (action, rule_id, severity, msg, country) in enumerate([
        ("deny", "1", "CRITICAL", "XSS", "US"),
        ("deny", "1", "CRITICAL", "XSS", "US"),
        ("drop", "2", "HIGH", "SQLi", "CA"),
    ]):
        db.add(
            WafMetric(
                captured_at=(now - timedelta(seconds=i)).replace(tzinfo=None),
                action=action,
                rule_id=rule_id,
                severity=severity,
                msg=msg,
                client=f"1.2.3.{i}",
                country=country,
                uri=f"/{i}",
            )
        )
    db.commit()

    result = waf_metrics.get_waf_metrics(db, start=now - timedelta(minutes=5), breakdown="action")
    assert result["totals"] == {"deny": 2, "drop": 1}

    result = waf_metrics.get_waf_metrics(db, start=now - timedelta(minutes=5), breakdown="rule_id")
    assert result["totals"] == {"1": 2, "2": 1}

    result = waf_metrics.get_waf_metrics(db, start=now - timedelta(minutes=5), breakdown="country")
    assert result["totals"] == {"US": 2, "CA": 1}


def test_get_waf_metrics_empty(db):
    now = datetime.now(timezone.utc)
    result = waf_metrics.get_waf_metrics(db, start=now - timedelta(minutes=5), breakdown="action")
    assert result == {"time": [], "series": [], "breakdown": "action", "totals": {}}


def test_get_waf_metrics_msg_breakdown_collapses_anomaly_score(db):
    """CRS 'Inbound Anomaly Score Exceeded (Total Score N)' messages group together."""
    now = datetime.now(timezone.utc)
    for i, msg in enumerate([
        "Inbound Anomaly Score Exceeded (Total Score: 23)",
        "Inbound Anomaly Score Exceeded (Total Score: 15)",
        "Inbound Anomaly Score Exceeded (Total Score: 42)",
        "SQL Injection Attack",
    ]):
        db.add(
            WafMetric(
                captured_at=(now - timedelta(seconds=i)).replace(tzinfo=None),
                action="deny",
                rule_id="1",
                severity="CRITICAL",
                msg=msg,
                client=f"1.2.3.{i}",
                country="US",
                uri=f"/{i}",
            )
        )
    db.commit()

    result = waf_metrics.get_waf_metrics(db, start=now - timedelta(minutes=5), breakdown="msg")
    # The three varying-score anomaly messages collapse into one key
    assert result["totals"] == {
        "Inbound Anomaly Score Exceeded": 3,
        "SQL Injection Attack": 1,
    }


def test_prune_waf_metrics(db, monkeypatch):
    monkeypatch.setattr(waf_metrics.settings, "WAF_METRICS_RETENTION_DAYS", 1)
    old = WafMetric(
        captured_at=(datetime.now(timezone.utc) - timedelta(days=2)).replace(tzinfo=None),
        action="deny",
        rule_id="1",
    )
    new = WafMetric(
        captured_at=datetime.now(timezone.utc).replace(tzinfo=None),
        action="deny",
        rule_id="1",
    )
    db.add(old)
    db.add(new)
    db.commit()

    deleted = waf_metrics.prune_waf_metrics(db)
    assert deleted == 1
    assert db.query(WafMetric).count() == 1


def test_prune_waf_log_file(temp_coraza_paths, monkeypatch):
    """prune_waf_log_file keeps only the last N lines and resets the offset."""
    monkeypatch.setattr(waf_metrics.settings, "WAF_LOG_RETENTION_LINES", 3)
    log_path = temp_coraza_paths["log"]

    # Write 5 lines to the log file.
    with open(log_path, "w") as f:
        for i in range(5):
            f.write(f"line {i}\n")

    # Set a non-zero offset to verify it gets reset.
    waf_metrics._write_offset(999)

    removed = waf_metrics.prune_waf_log_file()
    assert removed == 2

    with open(log_path) as f:
        remaining = f.readlines()
    assert len(remaining) == 3
    assert remaining[0].strip() == "line 2"
    assert remaining[-1].strip() == "line 4"

    # Offset should be reset to 0 after pruning.
    assert waf_metrics._read_offset() == 0


def test_prune_waf_log_file_noop_when_under_limit(temp_coraza_paths, monkeypatch):
    """prune_waf_log_file does nothing when the file is within the limit."""
    monkeypatch.setattr(waf_metrics.settings, "WAF_LOG_RETENTION_LINES", 500)
    log_path = temp_coraza_paths["log"]

    with open(log_path, "w") as f:
        f.write("line 0\nline 1\n")

    removed = waf_metrics.prune_waf_log_file()
    assert removed == 0

    with open(log_path) as f:
        assert len(f.readlines()) == 2


def test_prune_waf_log_file_disabled(temp_coraza_paths, monkeypatch):
    """WAF_LOG_RETENTION_LINES=0 disables pruning entirely."""
    monkeypatch.setattr(waf_metrics.settings, "WAF_LOG_RETENTION_LINES", 0)
    log_path = temp_coraza_paths["log"]

    with open(log_path, "w") as f:
        for i in range(10):
            f.write(f"line {i}\n")

    removed = waf_metrics.prune_waf_log_file()
    assert removed == 0

    with open(log_path) as f:
        assert len(f.readlines()) == 10


def test_prune_waf_log_file_missing_file(temp_coraza_paths, monkeypatch):
    """prune_waf_log_file returns 0 when the log file doesn't exist."""
    monkeypatch.setattr(waf_metrics.settings, "WAF_LOG_RETENTION_LINES", 3)
    # Don't create the log file — temp_coraza_paths only sets the paths.
    removed = waf_metrics.prune_waf_log_file()
    assert removed == 0
