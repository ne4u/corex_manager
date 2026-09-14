"""Tests for the 2-query first/last-per-bucket row reduction in get_metrics.

The existing test_metrics.py covers a single-bucket end-to-end case; these
tests cover multi-bucket aggregation and verify that only first/last snapshots
per bucket are needed (lossless vs. the old load-all approach). Uses the ``db``
fixture so tables are truncated between tests (no leftover-snapshot pollution).
"""

from datetime import UTC, datetime, timedelta

from app.models.models import MetricSnapshot
from app.services import metrics


def _fe_row(pxname, svname="FRONTEND", **kw):
    row = {"pxname": pxname, "svname": svname, "type": "0"}
    row.update(kw)
    return row


def test_get_metrics_multi_bucket_uses_first_and_last_per_bucket(db):
    """Three snapshots across two buckets: each bucket's rate must be derived
    from its own first/last pair, not from all rows."""
    # Align base to a 60s bucket boundary so the offsets below are deterministic
    # regardless of when the test runs.
    now = datetime.now(UTC)
    base_epoch = int(now.timestamp()) // 60 * 60
    base = datetime.fromtimestamp(base_epoch, tz=UTC).replace(tzinfo=None)
    # Bucket A (step=60, the bucket ending at base): snapshots at base-50s and
    #   base-20s (delta 30s, 2xx 100->160).
    # Bucket B (step=60, the bucket starting at base): snapshot at base
    #   (2xx 160->260) — single snapshot, duration falls back to prev_snapshot
    #   (last of bucket A = base-20s).
    db.add_all(
        [
            MetricSnapshot(
                captured_at=base - timedelta(seconds=50),
                process_info={"Idle_pct": "80", "CurrConns": "5", "Maxconn": "100"},
                stats=[_fe_row("fe1", hrsp_2xx="100", bin="0", bout="0")],
            ),
            MetricSnapshot(
                captured_at=base - timedelta(seconds=20),
                process_info={"Idle_pct": "75", "CurrConns": "6", "Maxconn": "100"},
                stats=[_fe_row("fe1", hrsp_2xx="160", bin="3000", bout="6000")],
            ),
            MetricSnapshot(
                captured_at=base,
                process_info={"Idle_pct": "70", "CurrConns": "7", "Maxconn": "100"},
                stats=[_fe_row("fe1", hrsp_2xx="260", bin="6000", bout="12000")],
            ),
        ]
    )
    db.commit()

    points = metrics.get_metrics(db, base - timedelta(minutes=5), base, step=60)
    assert len(points) == 2, f"expected 2 buckets, got {len(points)}"

    # Bucket A: first=100, last=160, duration=30s -> rate = 60/30 = 2.0/s
    a = points[0]
    assert a["frontend"]["responses_rate"] == 2.0
    assert a["process"]["current_connections"] == 6  # last snapshot's CurrConns

    # Bucket B: single snapshot, duration falls back to prev_snapshot (last of A).
    # delta = 260-160 = 100 over (base - (base-20s)) = 20s -> 5.0/s
    b = points[1]
    assert b["frontend"]["responses_rate"] == 5.0
    assert b["process"]["current_connections"] == 7


def test_get_metrics_empty_range_returns_empty(db):
    now = datetime.now(UTC).replace(tzinfo=None)
    assert metrics.get_metrics(db, now - timedelta(minutes=5), now, step=60) == []


def test_get_metrics_single_snapshot_uses_sample_interval(db):
    """A single snapshot in a bucket with no predecessor uses the configured
    sample interval as the duration denominator."""
    now = datetime.now(UTC).replace(tzinfo=None)
    db.add(
        MetricSnapshot(
            captured_at=now,
            process_info={"Idle_pct": "50", "CurrConns": "1", "Maxconn": "100"},
            stats=[_fe_row("fe1", hrsp_2xx="10", bin="0", bout="0")],
        )
    )
    db.commit()
    points = metrics.get_metrics(db, now - timedelta(minutes=5), now, step=60)
    assert len(points) == 1
    # With no first row, rates are 0 (no delta). The point still has process info.
    assert points[0]["process"]["current_connections"] == 1
    assert points[0]["frontend"]["responses_rate"] == 0.0
