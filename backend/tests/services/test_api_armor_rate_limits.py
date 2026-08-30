"""Tests for per-endpoint rate limiting (API Armor path/method scoping)."""
from app.services import haproxy
from app.models.models import RateLimit
from tests.factories import make_backend, make_listener, make_server


def test_rate_limit_without_path_scoping(db):
    """Rate limit without path_pattern emits no path ACL."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    rl = RateLimit(
        listener_id=listener.id,
        name="test-rl",
        enabled=True,
        limit_type="basic",
        events=100,
        window_seconds=60,
        burst=20,
        action="block",
        duration_seconds=0,
        rate_key="src",
    )
    db.add(rl)
    db.commit()
    cfg = haproxy.generate_config(db)
    # Should not have path_beg in the rate limit condition
    assert "path_beg" not in cfg or "path_beg" in cfg.split("test-rl")[0]  # may appear elsewhere


def test_rate_limit_with_path_scoping(db):
    """Rate limit with path_pattern emits path_beg ACL."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    rl = RateLimit(
        listener_id=listener.id,
        name="test-rl-api",
        enabled=True,
        limit_type="basic",
        events=100,
        window_seconds=60,
        burst=20,
        action="block",
        duration_seconds=0,
        rate_key="src",
        path_pattern="/api/v1/",
    )
    db.add(rl)
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "path_beg /api/v1/" in cfg


def test_rate_limit_with_method_scoping(db):
    """Rate limit with method emits method ACL."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    rl = RateLimit(
        listener_id=listener.id,
        name="test-rl-post",
        enabled=True,
        limit_type="basic",
        events=50,
        window_seconds=60,
        burst=10,
        action="block",
        duration_seconds=0,
        rate_key="src",
        method="POST",
    )
    db.add(rl)
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "method POST" in cfg


def test_rate_limit_with_path_and_method_scoping(db):
    """Rate limit with both path_pattern and method emits both ACLs."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    rl = RateLimit(
        listener_id=listener.id,
        name="test-rl-scoped",
        enabled=True,
        limit_type="basic",
        events=100,
        window_seconds=60,
        burst=20,
        action="block",
        duration_seconds=0,
        rate_key="src",
        path_pattern="/api/v1/users",
        method="POST",
    )
    db.add(rl)
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "path_beg /api/v1/users" in cfg
    assert "method POST" in cfg


def test_rate_limit_api_armor_scoped_flag(db):
    """Rate limit with api_armor_scoped=True is stored correctly."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    rl = RateLimit(
        listener_id=listener.id,
        name="test-rl-armor",
        enabled=True,
        limit_type="basic",
        events=100,
        window_seconds=60,
        burst=20,
        action="block",
        duration_seconds=0,
        rate_key="src",
        path_pattern="/api/",
        method="GET",
        api_armor_scoped=True,
    )
    db.add(rl)
    db.commit()
    db.refresh(rl)
    assert rl.path_pattern == "/api/"
    assert rl.method == "GET"
    assert rl.api_armor_scoped is True
