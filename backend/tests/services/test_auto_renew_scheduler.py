"""Restart-safety tests for the AutoRenewScheduler."""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.services import tasks
from app.services.tasks import AutoRenewScheduler


def _set_last_run_at(db, dt):
    """Write the auto_renew_last_run_at setting directly."""
    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "auto_renew_last_run_at"
    ).first()
    if not row:
        row = Setting(key="auto_renew_last_run_at", value=dt.isoformat())
        db.add(row)
    else:
        row.value = dt.isoformat()
    db.commit()


def test_auto_renew_skips_initial_tick_when_recently_run(db):
    """A recent last_run_at => queue_task not called on the initial _run tick."""
    scheduler = AutoRenewScheduler()
    recent = datetime.now(timezone.utc) - timedelta(seconds=60)
    _set_last_run_at(db, recent)

    mock_queue = MagicMock()

    with patch("app.services.tasks.SessionLocal") as mock_session:
        mock_session.return_value.__enter__.return_value = db
        mock_session.return_value.__exit__.return_value = False
        with patch("app.services.tasks.queue_task", mock_queue):
            # Simulate the initial branch of _run
            if scheduler._is_due():
                scheduler._run_tick()
            # Not due => _run_tick should not have been called

    mock_queue.assert_not_called()


def test_auto_renew_runs_immediately_when_never_run(db):
    """No last_run_at setting => queue_task called immediately."""
    scheduler = AutoRenewScheduler()

    mock_queue = MagicMock()

    with patch("app.services.tasks.SessionLocal") as mock_session:
        mock_session.return_value.__enter__.return_value = db
        mock_session.return_value.__exit__.return_value = False
        with patch("app.services.tasks.queue_task", mock_queue):
            assert scheduler._is_due() is True
            scheduler._run_tick()

    mock_queue.assert_called_once_with("auto_renew")


def test_auto_renew_stamps_on_queue(db):
    """queue_task called => auto_renew_last_run_at is stamped."""
    scheduler = AutoRenewScheduler()

    mock_queue = MagicMock()

    with patch("app.services.tasks.SessionLocal") as mock_session:
        mock_session.return_value.__enter__.return_value = db
        mock_session.return_value.__exit__.return_value = False
        with patch("app.services.tasks.queue_task", mock_queue):
            scheduler._run_tick()

    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "auto_renew_last_run_at"
    ).first()
    assert row is not None
    assert row.value is not None


def test_auto_renew_disabled_stamps_and_skips(db, monkeypatch):
    """When AUTO_RENEW_ENABLED is false, queue_task is NOT called but last_run_at IS stamped."""
    monkeypatch.setattr(tasks.settings, "AUTO_RENEW_ENABLED", False)
    scheduler = AutoRenewScheduler()

    mock_queue = MagicMock()

    with patch("app.services.tasks.SessionLocal") as mock_session:
        mock_session.return_value.__enter__.return_value = db
        mock_session.return_value.__exit__.return_value = False
        with patch("app.services.tasks.queue_task", mock_queue):
            # _run_tick is void; _tick returns True (disabled) so stamp should occur
            scheduler._run_tick()

    mock_queue.assert_not_called()
    from app.models.models import Setting
    row = db.query(Setting).filter(
        Setting.key == "auto_renew_last_run_at"
    ).first()
    assert row is not None
    assert row.value is not None
