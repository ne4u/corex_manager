from datetime import datetime, timedelta, timezone

import pytest

from app.services import metrics


def _fe_row(pxname, svname="FRONTEND", **kw):
    row = {"pxname": pxname, "svname": svname, "type": "0"}
    row.update(kw)
    return row


def _be_row(pxname, svname="BACKEND", **kw):
    row = {"pxname": pxname, "svname": svname, "type": "1"}
    row.update(kw)
    return row


def _srv_row(pxname, svname, **kw):
    row = {"pxname": pxname, "svname": svname, "type": "2"}
    row.update(kw)
    return row


def test_responses_rate_zero_without_first_rows():
    rows = [_be_row("be1", hrsp_2xx="100", hrsp_1xx="0", hrsp_3xx="0", hrsp_4xx="0", hrsp_5xx="0", hrsp_other="0")]
    result = metrics._derive_backend_metrics(rows, None, 30.0)
    assert result["responses_rate"] == 0.0


def test_responses_rate_from_response_deltas():
    first = [_be_row("be1", hrsp_2xx="100", hrsp_1xx="0", hrsp_3xx="0", hrsp_4xx="0", hrsp_5xx="0", hrsp_other="0")]
    rows = [_be_row("be1", hrsp_2xx="160", hrsp_1xx="5", hrsp_3xx="0", hrsp_4xx="10", hrsp_5xx="0", hrsp_other="0")]
    result = metrics._derive_backend_metrics(rows, first, 30.0)
    # delta = (60 + 5 + 0 + 10 + 0 + 0) = 75 over 30s = 2.5/s
    assert result["responses_rate"] == pytest.approx(2.5)


def test_per_proxy_byte_rates_populated():
    first = [
        _fe_row("fe1", bin="1000", bout="2000"),
        _fe_row("fe2", bin="500", bout="700"),
    ]
    rows = [
        _fe_row("fe1", bin="4000", bout="8000"),
        _fe_row("fe2", bin="1500", bout="1700"),
    ]
    agg = metrics._aggregate(rows, first, 10.0)
    fe1 = agg["frontends"]["fe1"]
    fe2 = agg["frontends"]["fe2"]
    assert fe1["bytes_in_rate"] == pytest.approx(300.0)   # (4000-1000)/10
    assert fe1["bytes_out_rate"] == pytest.approx(600.0)  # (8000-2000)/10
    assert fe2["bytes_in_rate"] == pytest.approx(100.0)   # (1500-500)/10
    assert fe2["bytes_out_rate"] == pytest.approx(100.0)  # (1700-700)/10


def test_per_proxy_responses_rate_populated():
    first = [_be_row("be1", hrsp_2xx="100", hrsp_1xx="0", hrsp_3xx="0", hrsp_4xx="0", hrsp_5xx="0", hrsp_other="0")]
    rows = [_be_row("be1", hrsp_2xx="200", hrsp_1xx="0", hrsp_3xx="0", hrsp_4xx="0", hrsp_5xx="0", hrsp_other="0")]
    agg = metrics._aggregate(rows, first, 20.0)
    assert agg["backends"]["be1"]["responses_rate"] == pytest.approx(5.0)  # 100/20


def test_denials_rate_zero_without_first_rows():
    """Without a prior snapshot, denials_rate is 0 (can't compute a delta)."""
    rows = [_fe_row("fe1", dreq="100", dresp="50")]
    result = metrics._derive_proxy_metrics(rows, None, 30.0)
    assert result["denials_rate"] == 0.0
    # The raw cumulative value is still available for reference
    assert result["denials"] == 150


def test_denials_rate_from_dreq_dresp_deltas():
    """denials_rate is derived from dreq + dresp cumulative counter deltas."""
    first = [_fe_row("fe1", dreq="100", dresp="50")]
    rows = [_fe_row("fe1", dreq="130", dresp="65")]
    result = metrics._derive_proxy_metrics(rows, first, 10.0)
    # delta = (130-100) + (65-50) = 30 + 15 = 45 over 10s = 4.5/s
    assert result["denials_rate"] == pytest.approx(4.5)


def test_denials_rate_handles_counter_reset():
    """A counter reset (HAProxy restart) clamps the delta to 0, not negative."""
    first = [_fe_row("fe1", dreq="500", dresp="200")]
    rows = [_fe_row("fe1", dreq="5", dresp="2")]
    result = metrics._derive_proxy_metrics(rows, first, 10.0)
    # Both deltas are negative → clamped to 0
    assert result["denials_rate"] == 0.0


def test_denials_rate_in_aggregate():
    """denials_rate is populated in both frontend and backend aggregate dicts."""
    first = [
        _fe_row("fe1", dreq="10", dresp="5"),
        _be_row("be1", dreq="20", dresp="10"),
    ]
    rows = [
        _fe_row("fe1", dreq="40", dresp="15"),
        _be_row("be1", dreq="50", dresp="30"),
    ]
    agg = metrics._aggregate(rows, first, 10.0)
    # Frontend: (40-10) + (15-5) = 30 + 10 = 40 / 10 = 4.0/s
    assert agg["frontend"]["denials_rate"] == pytest.approx(4.0)
    # Backend: (50-20) + (30-10) = 30 + 20 = 50 / 10 = 5.0/s
    assert agg["backend"]["denials_rate"] == pytest.approx(5.0)


def test_per_server_rates_from_matched_first_row():
    first = [_srv_row("be1", "srvA", hrsp_2xx="10", bin="100", bout="200")]
    rows = [_srv_row("be1", "srvA", hrsp_2xx="60", bin="600", bout="1200")]
    agg = metrics._aggregate(rows, first, 10.0)
    s = agg["servers"]["be1"]["srvA"]
    assert s["requests_rate"] == pytest.approx(5.0)   # (60-10)/10
    assert s["bytes_in_rate"] == pytest.approx(50.0)  # (600-100)/10
    assert s["bytes_out_rate"] == pytest.approx(100.0)  # (1200-200)/10


def test_per_server_zero_rates_without_first_row():
    rows = [_srv_row("be1", "srvA", hrsp_2xx="60", bin="600", bout="1200")]
    agg = metrics._aggregate(rows, None, 10.0)
    s = agg["servers"]["be1"]["srvA"]
    assert s["requests_rate"] == 0.0
    assert s["bytes_in_rate"] == 0.0
    assert s["bytes_out_rate"] == 0.0


def test_per_server_matching_uses_pxname_svname_key():
    # Two backends each with a server named "srvA" — deltas must not cross-match.
    first = [
        _srv_row("be1", "srvA", hrsp_2xx="10", bin="100", bout="200"),
        _srv_row("be2", "srvA", hrsp_2xx="1000", bin="10000", bout="20000"),
    ]
    rows = [
        _srv_row("be1", "srvA", hrsp_2xx="60", bin="600", bout="1200"),
        _srv_row("be2", "srvA", hrsp_2xx="1100", bin="11000", bout="22000"),
    ]
    agg = metrics._aggregate(rows, first, 10.0)
    s1 = agg["servers"]["be1"]["srvA"]
    s2 = agg["servers"]["be2"]["srvA"]
    assert s1["requests_rate"] == pytest.approx(5.0)     # be1 delta = 50
    assert s2["requests_rate"] == pytest.approx(10.0)    # be2 delta = 100
    assert s1["bytes_in_rate"] == pytest.approx(50.0)
    assert s2["bytes_in_rate"] == pytest.approx(100.0)


def test_get_metrics_end_to_end(tmp_path, monkeypatch):
    """Two snapshots 30s apart produce one bucket with derived rates."""
    from app.models.models import MetricSnapshot
    from app.core.database import SessionLocal

    # Tables are created once at session scope by the _session_schema fixture.
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        first = MetricSnapshot(
            captured_at=now - timedelta(seconds=30),
            process_info={"Idle_pct": "80", "CurrConns": "5", "Maxconn": "100"},
            stats=[_fe_row("fe1", req_rate="10", bin="1000", bout="2000",
                           hrsp_2xx="100", hrsp_1xx="0", hrsp_3xx="0",
                           hrsp_4xx="0", hrsp_5xx="0", hrsp_other="0")],
        )
        second = MetricSnapshot(
            captured_at=now,
            process_info={"Idle_pct": "70", "CurrConns": "7", "Maxconn": "100"},
            stats=[_fe_row("fe1", req_rate="12", bin="4000", bout="8000",
                           hrsp_2xx="160", hrsp_1xx="0", hrsp_3xx="0",
                           hrsp_4xx="0", hrsp_5xx="0", hrsp_other="0")],
        )
        db.add_all([first, second])
        db.commit()

        points = metrics.get_metrics(db, now - timedelta(minutes=5), now, step=60)
        assert points, "expected at least one metric point"
        p = points[-1]
        # responses_rate derived from hrsp_2xx delta of 60 over 30s = 2.0/s
        assert p["frontend"]["responses_rate"] == pytest.approx(2.0)
        # bytes rates derived from cumulative deltas
        assert p["frontend"]["bytes_in_rate"] == pytest.approx(100.0)   # 3000/30
        assert p["frontend"]["bytes_out_rate"] == pytest.approx(200.0)  # 6000/30
        # per-proxy dict also populated
        assert p["frontends"]["fe1"]["responses_rate"] == pytest.approx(2.0)
    finally:
        db.close()
