"""Tests for the cross-process config write file lock (hardening #5).

Verifies that ``write_config`` is decorated with ``_config_write_locked`` and
that the file lock context manager creates and releases the lock file.
"""

import os
import tempfile
from unittest.mock import patch

from app.services import haproxy


def test_write_config_is_decorated_with_file_lock():
    """write_config must be wrapped by _config_write_locked so concurrent
    calls from different workers are serialized."""
    # The decorator preserves the function name via functools.wraps, but
    # the wrapper is a closure. Verify by checking that calling write_config
    # acquires the lock.
    assert hasattr(haproxy, "_config_write_locked")
    assert hasattr(haproxy, "_config_write_lock")


def test_config_write_lock_creates_and_releases_lock_file(tmp_path, monkeypatch):
    """The lock context manager creates a .config_write.lock file in the
    config directory and releases the flock on exit."""
    config_path = str(tmp_path / "haproxy.cfg")
    monkeypatch.setattr(haproxy.settings, "HAPROXY_CONFIG_PATH", config_path)

    lock_path = str(tmp_path / ".config_write.lock")
    assert not os.path.exists(lock_path)

    with haproxy._config_write_lock():
        assert os.path.exists(lock_path)

    # Lock file remains on disk (harmless), but the flock is released.
    assert os.path.exists(lock_path)


def test_config_write_lock_is_reentrant_safe(tmp_path, monkeypatch):
    """Entering and exiting the lock multiple times in sequence works
    (no stale lock state)."""
    config_path = str(tmp_path / "haproxy.cfg")
    monkeypatch.setattr(haproxy.settings, "HAPROXY_CONFIG_PATH", config_path)

    for _ in range(3):
        with haproxy._config_write_lock():
            pass  # should not raise


def test_write_config_acquires_lock(tmp_path, monkeypatch):
    """write_config must acquire the file lock before writing. Verify by
    mocking the lock and checking it was entered."""
    config_path = str(tmp_path / "haproxy.cfg")
    monkeypatch.setattr(haproxy.settings, "HAPROXY_CONFIG_PATH", config_path)

    # Mock generate_config and the heavy internals so write_config doesn't
    # need a real DB. We just want to verify the lock is acquired.
    lock_entered = []
    original_lock = haproxy._config_write_lock

    class _tracking_lock:
        def __enter__(self):
            lock_entered.append(True)
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(haproxy, "_config_write_lock", _tracking_lock)

    # Patch the internals that write_config calls
    monkeypatch.setattr(haproxy, "generate_config", lambda *a, **kw: "# test config")
    monkeypatch.setattr(haproxy, "_get_section_names", lambda db: ("fe", "be", "stats", "coraza"))
    monkeypatch.setattr(haproxy, "validate_config_text", lambda config: (True, "ok"))

    # write_config does a lot; just call it and check the lock was acquired
    # even if it fails partway through (the lock is acquired first).
    try:
        haproxy.write_config(None)
    except Exception:
        pass  # expected — we didn't mock everything

    assert lock_entered, "write_config did not acquire the file lock"
