"""Tests for the PeriodicTask restart-safe scheduler base class."""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.services.scheduler import PeriodicTask, _parse_iso


class _RecordingTask(PeriodicTask):
    """Test double that records _tick calls and returns a configurable result."""

    def __init__(self, name="test_task", interval_seconds=3600,
                 files_required=None, tick_return=True, tick_raises=None):
        super().__init__(name=name, interval_seconds=interval_seconds,
                         files_required=files_required)
        self.tick_calls = 0
        self._tick_return = tick_return
        self._tick_raises = tick_raises

    def _tick(self) -> bool:
        self.tick_calls += 1
        if self._tick_raises:
            raise self._tick_raises
        return self._tick_return


def _set_last_run_at(db, key, dt):
    """Write a last_run_at setting directly."""
    from app.models.models import Setting
    row = db.query(Setting).filter(Setting.key == key).first()
    if not row:
        row = Setting(key=key, value=dt.isoformat())
        db.add(row)
    else:
        row.value = dt.isoformat()
    db.commit()


def _patch_sessionlocal(db):
    """Patch scheduler.SessionLocal so it yields the test db session."""
    mock = MagicMock()
    mock.return_value.__enter__.return_value = db
    mock.return_value.__exit__.return_value = False
    return patch("app.services.scheduler.SessionLocal", mock)


def test_parse_iso_with_and_without_tzinfo():
    """_parse_iso handles tz-aware and naive ISO strings."""
    aware = _parse_iso("2026-01-02T03:04:05+00:00")
    assert aware is not None
    assert aware.tzinfo is not None

    naive = _parse_iso("2026-01-02T03:04:05")
    assert naive is not None
    assert naive.tzinfo is not None  # treated as UTC

    assert _parse_iso("not-a-date") is None
    assert _parse_iso(None) is None


def test_periodic_task_skips_initial_tick_when_not_due(db):
    """When last_run_at is recent, _tick is not called on the initial _run tick."""
    task = _RecordingTask(name="test_skip", interval_seconds=3600)
    recent = datetime.now(timezone.utc) - timedelta(seconds=10)
    _set_last_run_at(db, "test_skip_last_run_at", recent)

    with _patch_sessionlocal(db):
        # _is_due should be False (10s elapsed < 3600s interval)
        assert task._is_due() is False
        # _run_tick should NOT be called on the initial pass.
        # We simulate the initial branch of _run directly:
        if task._is_due():
            task._run_tick()
        else:
            # would sleep; we don't actually wait
            pass

    assert task.tick_calls == 0


def test_periodic_task_runs_initial_tick_when_due(db):
    """When no last_run_at setting exists, _tick is called immediately."""
    task = _RecordingTask(name="test_due", interval_seconds=3600)

    with _patch_sessionlocal(db):
        assert task._is_due() is True
        task._run_tick()

    assert task.tick_calls == 1


def test_periodic_task_runs_when_required_file_missing(db):
    """Even with a recent last_run_at, missing required file => due."""
    task = _RecordingTask(
        name="test_file_missing",
        interval_seconds=3600,
        files_required=["/nonexistent/path/that/does/not/exist.mmdb"],
    )
    recent = datetime.now(timezone.utc) - timedelta(seconds=10)
    _set_last_run_at(db, "test_file_missing_last_run_at", recent)

    with _patch_sessionlocal(db):
        assert task._is_due() is True


def test_periodic_task_stamps_on_success(db):
    """_tick returning True stamps last_run_at in the settings table."""
    task = _RecordingTask(name="test_stamp_ok", interval_seconds=3600,
                          tick_return=True)

    with _patch_sessionlocal(db):
        task._run_tick()

    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "test_stamp_ok_last_run_at"
    ).first()
    assert row is not None
    assert row.value is not None
    # The stamped value should be a parseable ISO timestamp
    assert _parse_iso(row.value) is not None


def test_periodic_task_does_not_stamp_on_failure(db):
    """_tick returning False does not stamp last_run_at."""
    task = _RecordingTask(name="test_stamp_fail", interval_seconds=3600,
                          tick_return=False)

    with _patch_sessionlocal(db):
        task._run_tick()

    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "test_stamp_fail_last_run_at"
    ).first()
    assert row is None


def test_periodic_task_does_not_stamp_on_exception(db):
    """_tick raising an exception does not stamp and does not crash."""
    task = _RecordingTask(name="test_stamp_exc", interval_seconds=3600,
                          tick_raises=RuntimeError("boom"))

    with _patch_sessionlocal(db):
        # Should not raise
        task._run_tick()

    assert task.tick_calls == 1
    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "test_stamp_exc_last_run_at"
    ).first()
    assert row is None


def test_periodic_task_remaining_seconds_when_not_due(db):
    """_remaining_seconds returns the time left until due."""
    task = _RecordingTask(name="test_remaining", interval_seconds=3600)
    # Set last_run_at to 10 seconds ago -> ~3590s remaining
    recent = datetime.now(timezone.utc) - timedelta(seconds=10)
    _set_last_run_at(db, "test_remaining_last_run_at", recent)

    with _patch_sessionlocal(db):
        remaining = task._remaining_seconds()

    # Allow some slack for test execution time
    assert 3580 <= remaining <= 3600


def test_periodic_task_remaining_seconds_zero_when_due(db):
    """_remaining_seconds returns 0 when no last_run_at exists."""
    task = _RecordingTask(name="test_remaining_zero", interval_seconds=3600)

    with _patch_sessionlocal(db):
        remaining = task._remaining_seconds()

    assert remaining == 0.0
