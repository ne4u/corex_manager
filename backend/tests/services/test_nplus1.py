"""Tests that list endpoints issue a bounded number of SQL queries (no N+1).

Uses SQLAlchemy's ``before_cursor_execute`` event on the engine to count
queries issued within a list call. The count must stay constant as the number
of rows grows.
"""

from sqlalchemy import event
from sqlalchemy.orm import selectinload

from app.models.models import (
    AsnList,
    AsnListEntry,
    Backend,
    GeoList,
    GeoListEntry,
    Ja4List,
    Ja4ListEntry,
    NetworkList,
    NetworkListEntry,
    PatternList,
    PatternListEntry,
)
from app.services.backends import list_backends
from tests.factories import make_backend, make_server


def _count_queries(db, fn):
    """Run ``fn`` and return the number of SQL statements it issued."""
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


def test_list_backends_query_count_is_constant(db):
    """list_backends must use selectinload(servers) — query count is constant
    regardless of how many backends exist (1 + 1 selectinload = 2)."""
    counter = [0]

    def make(n):
        for _ in range(n):
            i = counter[0]
            counter[0] += 1
            b = make_backend(db, name=f"be-{i}")
            make_server(db, backend_id=b.id, name=f"s-{i}-a", address=f"10.0.{i}.1")
            make_server(db, backend_id=b.id, name=f"s-{i}-b", address=f"10.0.{i}.2")
        db.commit()

    make(1)
    n1 = _count_queries(db, lambda: list_backends(db))
    # Force the relationship to load to prove eager loading worked.
    for b in list_backends(db):
        _ = list(b.servers)

    # Add more backends and confirm the count doesn't grow.
    make(5)
    n6 = _count_queries(db, lambda: list_backends(db))
    for b in list_backends(db):
        _ = list(b.servers)

    assert n1 == n6, f"query count grew from {n1} to {n6} (N+1 present)"


def _test_list_constant(db, model_cls, entry_cls, make_entry, response_fn, prefix):
    counter = [0]

    def make(n):
        for _ in range(n):
            i = counter[0]
            counter[0] += 1
            lst = model_cls(name=f"{prefix}-{i}")
            db.add(lst)
            db.flush()
            for j in range(3):
                db.add(entry_cls(list_id=lst.id, value=make_entry(i, j)))
        db.commit()

    def call():
        rows = db.query(model_cls).options(selectinload(model_cls.entries)).all()
        for lst in rows:
            response_fn(lst)

    make(1)
    n1 = _count_queries(db, call)
    make(4)
    n5 = _count_queries(db, call)
    assert n1 == n5, f"query count grew from {n1} to {n5} (N+1 present)"


def test_list_network_lists_query_count_is_constant(db):
    from app.api.v1.security_lists import _network_list_response

    _test_list_constant(
        db, NetworkList, NetworkListEntry,
        lambda i, j: f"10.0.{i}.{j}/32", _network_list_response, "n",
    )


def test_list_asn_lists_query_count_is_constant(db):
    from app.api.v1.security_lists import _asn_list_response

    _test_list_constant(
        db, AsnList, AsnListEntry,
        lambda i, j: f"AS{i}{j}", _asn_list_response, "a",
    )


def test_list_geo_lists_query_count_is_constant(db):
    from app.api.v1.security_lists import _geo_list_response

    _test_list_constant(
        db, GeoList, GeoListEntry,
        lambda i, j: "US", _geo_list_response, "g",
    )


def test_list_ja4_lists_query_count_is_constant(db):
    from app.api.v1.security_lists import _ja4_list_response

    _test_list_constant(
        db, Ja4List, Ja4ListEntry,
        lambda i, j: f"t13d1516h2_{i:08x}_{j:08x}", _ja4_list_response, "j",
    )


def test_list_pattern_lists_query_count_is_constant(db):
    from app.api.v1.security_lists import _pattern_list_response

    _test_list_constant(
        db, PatternList, PatternListEntry,
        lambda i, j: f"pattern-{i}-{j}", _pattern_list_response, "p",
    )
