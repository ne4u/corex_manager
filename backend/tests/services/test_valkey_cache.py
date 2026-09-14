"""Tests for the Valkey cache helpers: deterministic key hashing, invalidation,
single-key delete, and the leader-election lock (with graceful degradation)."""

from unittest.mock import MagicMock

from app.core import valkey_client


# ---------------------------------------------------------------------------
# _hash_key determinism
# ---------------------------------------------------------------------------


def test_hash_key_is_deterministic_for_equal_args():
    a = valkey_client._hash_key(("foo", 1), {"x": 1})
    b = valkey_client._hash_key(("foo", 1), {"x": 1})
    assert a == b


def test_hash_key_stable_across_kwarg_order():
    a = valkey_client._hash_key((), {"a": 1, "b": 2})
    b = valkey_client._hash_key((), {"b": 2, "a": 1})
    assert a == b


def test_hash_key_differs_for_different_args():
    a = valkey_client._hash_key(("foo",), {})
    b = valkey_client._hash_key(("bar",), {})
    assert a != b


def test_hash_key_skips_sqlalchemy_session():
    from sqlalchemy.orm import Session

    sess = MagicMock(spec=Session)
    # A Session arg must not change the digest (it's not part of cache identity).
    a = valkey_client._hash_key(("foo",), {})
    b = valkey_client._hash_key(("foo", sess), {})
    assert a == b


def test_hash_key_handles_unhashable_args():
    # Lists/dicts are unhashable but must not raise; they're stringified.
    a = valkey_client._hash_key(({"nested": [1, 2]},), {})
    assert isinstance(a, str) and len(a) == 64  # sha256 hex


# ---------------------------------------------------------------------------
# Degradation when Valkey is unavailable
# ---------------------------------------------------------------------------


def test_cache_get_returns_none_when_valkey_down(monkeypatch):
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    assert valkey_client.cache_get("anything") is None


def test_cache_set_returns_false_when_valkey_down(monkeypatch):
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    assert valkey_client.cache_set("k", {"v": 1}, ttl=5) is False


def test_cache_delete_returns_false_when_valkey_down(monkeypatch):
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    assert valkey_client.cache_delete("k") is False


def test_invalidate_returns_zero_when_valkey_down(monkeypatch):
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    assert valkey_client.invalidate("prefix") == 0


# ---------------------------------------------------------------------------
# invalidate + cache_delete with a mock client
# ---------------------------------------------------------------------------


def test_invalidate_scans_and_deletes_matching_keys(monkeypatch):
    client = MagicMock()
    # Two SCAN batches: first returns 2 keys + cursor 1, second returns 1 key + cursor 0.
    client.scan.side_effect = [
        (1, ["prefix:a", "prefix:b"]),
        (0, ["prefix:c"]),
    ]
    # delete returns the number of keys deleted per call: 2 then 1.
    client.delete.side_effect = [2, 1]
    monkeypatch.setattr(valkey_client, "_get_client", lambda: client)

    deleted = valkey_client.invalidate("prefix")
    assert deleted == 3
    # SCAN was called with the prefix:* pattern.
    assert client.scan.call_args_list[0].kwargs["match"] == "prefix:*"
    # delete was called with the matching keys of each batch.
    client.delete.assert_any_call("prefix:a", "prefix:b")
    client.delete.assert_any_call("prefix:c")


def test_cache_delete_calls_client_delete(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(valkey_client, "_get_client", lambda: client)
    assert valkey_client.cache_delete("the-key") is True
    client.delete.assert_called_once_with("the-key")


# ---------------------------------------------------------------------------
# Leader election lock
# ---------------------------------------------------------------------------


def test_acquire_leader_lock_when_valkey_down_falls_back_to_pg(monkeypatch):
    """When Valkey is unavailable, fall back to a PostgreSQL advisory lock.
    On the SQLite test DB (no advisory locks), this degrades to True — the
    single-worker fallback. On PostgreSQL, exactly one worker would win."""
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    # Reset any stale PG lock connection from a prior test.
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", None)
    assert valkey_client.acquire_leader_lock() is True


def test_acquire_leader_lock_valkey_down_pg_unavailable_returns_false(monkeypatch):
    """If both Valkey and the PG advisory lock are unavailable, return False
    rather than blindly becoming leader (prevents duplicate background services
    in a degraded multi-worker deployment)."""
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", None)
    # Simulate PG advisory lock failing (e.g. connection error)
    monkeypatch.setattr(valkey_client, "_pg_try_advisory_lock", lambda: False)
    assert valkey_client.acquire_leader_lock() is False


def test_acquire_leader_lock_succeeds_when_unheld(monkeypatch):
    client = MagicMock()
    client.set.return_value = True  # SET NX succeeded
    monkeypatch.setattr(valkey_client, "_get_client", lambda: client)
    assert valkey_client.acquire_leader_lock(ttl=30) is True
    client.set.assert_called_once()
    args, kwargs = client.set.call_args
    assert kwargs.get("nx") is True
    assert kwargs.get("ex") == 30


def test_acquire_leader_lock_fails_when_held(monkeypatch):
    client = MagicMock()
    client.set.return_value = None  # SET NX failed (key exists)
    monkeypatch.setattr(valkey_client, "_get_client", lambda: client)
    assert valkey_client.acquire_leader_lock(ttl=30) is False


def test_renew_leader_lock_when_valkey_down_falls_back_to_pg(monkeypatch):
    """When Valkey is unavailable, renewal falls back to the PG advisory lock.
    The PG lock is session-level (no TTL), so if we hold it we're still leader."""
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", None)
    # On SQLite, _pg_try_advisory_lock returns True (single-worker fallback)
    assert valkey_client.renew_leader_lock() is True


def test_renew_leader_lock_valkey_down_pg_held_returns_true(monkeypatch):
    """If we already hold the PG advisory lock, renewal is a no-op → True."""
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", MagicMock())  # non-None = holding
    assert valkey_client.renew_leader_lock() is True


def test_renew_leader_lock_uses_cas_script(monkeypatch):
    client = MagicMock()
    client.eval.return_value = 1  # renewed
    monkeypatch.setattr(valkey_client, "_get_client", lambda: client)
    assert valkey_client.renew_leader_lock(ttl=30) is True
    client.eval.assert_called_once()


def test_renew_leader_lock_returns_false_when_not_owner(monkeypatch):
    client = MagicMock()
    client.eval.return_value = 0  # CAS failed — another process owns it
    monkeypatch.setattr(valkey_client, "_get_client", lambda: client)
    assert valkey_client.renew_leader_lock(ttl=30) is False


def test_release_leader_lock_best_effort(monkeypatch):
    client = MagicMock()
    client.eval.return_value = 1
    monkeypatch.setattr(valkey_client, "_get_client", lambda: client)
    valkey_client.release_leader_lock()  # must not raise
    client.eval.assert_called_once()


def test_release_leader_lock_when_valkey_down_does_not_raise(monkeypatch):
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", None)
    valkey_client.release_leader_lock()  # must not raise


def test_release_leader_lock_releases_pg_advisory_lock(monkeypatch):
    """When Valkey is down and we hold the PG advisory lock, release closes
    the dedicated connection and resets the module-level state."""
    fake_conn = MagicMock()
    monkeypatch.setattr(valkey_client, "_get_client", lambda: None)
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", fake_conn)
    valkey_client.release_leader_lock()
    fake_conn.execute.assert_called_once()  # pg_advisory_unlock
    fake_conn.close.assert_called_once()
    assert valkey_client._pg_lock_conn is None


# ---------------------------------------------------------------------------
# PostgreSQL advisory lock fallback unit tests
# ---------------------------------------------------------------------------


def test_pg_try_advisory_lock_returns_true_on_sqlite(monkeypatch):
    """On SQLite (the test DB), _pg_try_advisory_lock returns True — the
    single-worker fallback since SQLite has no advisory locks."""
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", None)
    assert valkey_client._pg_try_advisory_lock() is True


def test_pg_try_advisory_lock_returns_true_if_already_holding(monkeypatch):
    """If we already hold the PG lock, _pg_try_advisory_lock short-circuits."""
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", MagicMock())
    assert valkey_client._pg_try_advisory_lock() is True


def test_pg_release_advisory_lock_noop_when_not_holding(monkeypatch):
    """Releasing when we don't hold the lock is a safe no-op."""
    monkeypatch.setattr(valkey_client, "_pg_lock_conn", None)
    valkey_client._pg_release_advisory_lock()  # must not raise
    assert valkey_client._pg_lock_conn is None


def test_leader_id_is_stable_per_process():
    assert valkey_client.leader_id() == valkey_client.leader_id()
    assert ":" in valkey_client.leader_id()
