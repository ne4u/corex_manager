"""Tests for cross-worker task cancellation.

The cancellation signal lives in Valkey (key: ``task:cancel:{id}``) so a
cancel request on a non-leader worker is seen by the leader's task worker.
The in-process ``_cancelled_tasks`` set is a fast-path cache.
"""

from unittest.mock import patch

from app.services import tasks


def test_cancel_task_sets_valkey_flag(db):
    """cancel_task must set the Valkey cross-worker flag, not just the
    in-process set."""
    with patch("app.services.tasks.cache_set") as mock_set:
        tasks.cancel_task(999)
    mock_set.assert_called_once()
    key = mock_set.call_args[0][0]
    assert key == "task:cancel:999"
    assert mock_set.call_args[0][1] == "1"


def test_is_cancelled_checks_valkey_when_not_in_process():
    """A cancel from another worker sets only the Valkey flag; _is_cancelled
    must see it via the Valkey check."""
    with patch("app.services.tasks.cache_get", return_value="1"):
        assert tasks._is_cancelled(42) is True
    # The Valkey hit should be cached in-process for subsequent fast checks.
    assert 42 in tasks._cancelled_tasks
    tasks._clear_cancelled(42)


def test_is_cancelled_returns_false_when_neither_set():
    """No in-process flag and no Valkey flag → not cancelled."""
    with patch("app.services.tasks.cache_get", return_value=None):
        assert tasks._is_cancelled(777) is False


def test_is_cancelled_in_process_fast_path_skips_valkey():
    """If the in-process set has the flag, Valkey is not queried."""
    tasks._cancelled_tasks.add(123)
    try:
        with patch("app.services.tasks.cache_get") as mock_get:
            assert tasks._is_cancelled(123) is True
            mock_get.assert_not_called()
    finally:
        tasks._cancelled_tasks.discard(123)


def test_clear_cancelled_removes_from_both():
    """_clear_cancelled must remove the in-process flag and delete the Valkey key."""
    tasks._cancelled_tasks.add(555)
    with patch("app.services.tasks.cache_delete") as mock_del:
        tasks._clear_cancelled(555)
    assert 555 not in tasks._cancelled_tasks
    mock_del.assert_called_once_with("task:cancel:555")


def test_is_cancelled_returns_false_when_valkey_down():
    """When Valkey is unavailable (cache_get returns None), _is_cancelled
    falls back to the in-process set only — correct for synchronous mode
    where the task runs on the same worker as the cancel request."""
    with patch("app.services.tasks.cache_get", return_value=None):
        assert tasks._is_cancelled(888) is False
