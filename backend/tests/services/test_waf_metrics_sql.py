"""Tests for the SQL GROUP BY pushdown in get_waf_metrics.

Verifies the query count is constant regardless of row count (the pushdown
returns one row per (bucket, breakdown_value) group instead of loading every
WafMetric row into Python).
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import event

from app.models.models import WafMetric
from app.services import waf_metrics


def _count_queries(db, fn):
    queries = []
    engine = db.get_bind()

    def _listener(*_args, **_kwargs):
        queries.append(1)

    event.listen(engine, "before_cursor_execute", _listener)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", _listener)
    return len(queries)


def _seed(db, n, action="deny", rule_id="1"):
    now = datetime.now(UTC).replace(tzinfo=None)
    for i in range(n):
        db.add(
            WafMetric(
                captured_at=(now - timedelta(seconds=i)).replace(tzinfo=None),
                action=action,
                rule_id=rule_id,
                severity="CRITICAL",
                msg=f"msg-{i % 3}",
                client=f"1.2.3.{i % 200}",
                country="US",
                uri=f"/{i}",
            )
        )
    db.commit()


def test_get_waf_metrics_query_count_is_constant(db):
    """Query count must not grow with the number of WafMetric rows."""
    now = datetime.now(UTC)

    _seed(db, 5)
    n5 = _count_queries(
        db, lambda: waf_metrics.get_waf_metrics(db, now - timedelta(minutes=5), breakdown="action")
    )

    _seed(db, 45)  # 50 total
    n50 = _count_queries(
        db, lambda: waf_metrics.get_waf_metrics(db, now - timedelta(minutes=5), breakdown="action")
    )

    assert n5 == n50, f"query count grew from {n5} to {n50} (pushdown not effective)"


def test_get_waf_metrics_rejects_unknown_breakdown(db):
    """An unknown breakdown column falls back to 'action' (whitelist guard)."""
    now = datetime.now(UTC)
    _seed(db, 3)
    result = waf_metrics.get_waf_metrics(db, now - timedelta(minutes=5), breakdown="action'; DROP TABLE--")
    assert result["breakdown"] == "action"
    assert result["totals"] == {"deny": 3}


def test_get_waf_metrics_country_breakdown(db):
    now = datetime.now(UTC)
    for i, country in enumerate(["US", "US", "CA", "DE"]):
        db.add(
            WafMetric(
                captured_at=(now - timedelta(seconds=i)).replace(tzinfo=None),
                action="deny",
                rule_id="1",
                severity="CRITICAL",
                msg="x",
                client=f"1.2.3.{i}",
                country=country,
                uri=f"/{i}",
            )
        )
    db.commit()
    result = waf_metrics.get_waf_metrics(db, now - timedelta(minutes=5), breakdown="country")
    assert result["totals"] == {"US": 2, "CA": 1, "DE": 1}
