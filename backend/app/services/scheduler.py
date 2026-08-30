"""Restart-safe periodic task base class.

Background services that do external work (downloads, API calls) on a fixed
interval should subclass ``PeriodicTask`` instead of rolling their own
``threading.Thread`` loop. ``PeriodicTask`` persists a ``last_run_at``
timestamp in the ``settings`` table so that a container restart does not
trigger redundant work or reset the schedule.

On startup the task checks whether it is "due" (timestamp age >= interval, or
any ``files_required`` are missing). If it is not due, it sleeps for the
remaining time until due instead of running immediately, preserving the
original schedule across restarts. ``last_run_at`` is stamped only when
``_tick`` returns ``True`` (success), so a failed run retries on the next
interval or restart rather than resetting the clock.
"""
import logging
import os
import threading
from datetime import datetime, timezone
from typing import List, Optional

from ..core.database import SessionLocal
from .settings import get_setting, set_setting

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (with or without tzinfo) into a datetime."""
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class PeriodicTask:
    """Base class for restart-safe periodic background tasks.

    Subclasses implement ``_tick(self) -> bool``. Returning ``True`` stamps
    ``last_run_at`` so the task won't re-run until the next interval elapses.
    Returning ``False`` or raising leaves ``last_run_at`` untouched so the
    task retries on the next interval or restart.
    """

    def __init__(
        self,
        name: str,
        interval_seconds: float,
        files_required: Optional[List[str]] = None,
        skip_initial_if_not_due: bool = True,
    ):
        self.name = name
        self.interval_seconds = interval_seconds
        self.files_required: List[str] = list(files_required or [])
        self.skip_initial_if_not_due = skip_initial_if_not_due
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # --- subclass hook -------------------------------------------------
    def _tick(self) -> bool:
        """Perform one unit of work. Return True on success to stamp last_run_at."""
        raise NotImplementedError

    # --- schedule helpers ----------------------------------------------
    @property
    def _setting_key(self) -> str:
        return f"{self.name}_last_run_at"

    def _last_run_at(self) -> Optional[datetime]:
        with SessionLocal() as db:
            value = get_setting(db, self._setting_key)
        if not value:
            return None
        return _parse_iso(value)

    def _is_due(self) -> bool:
        """Return True if the task should run now."""
        # Missing required file -> always due (handles fresh volume).
        for path in self.files_required:
            if not path or not os.path.exists(path):
                return True
        last = self._last_run_at()
        if last is None:
            return True
        elapsed = (_utcnow() - last).total_seconds()
        return elapsed >= self.interval_seconds

    def _remaining_seconds(self) -> float:
        """Seconds until the next due time (0 if already due)."""
        last = self._last_run_at()
        if last is None:
            return 0.0
        remaining = self.interval_seconds - (_utcnow() - last).total_seconds()
        return max(0.0, remaining)

    def _stamp(self) -> None:
        with SessionLocal() as db:
            set_setting(db, self._setting_key, _utcnow().isoformat())

    def _run_tick(self) -> None:
        try:
            ok = self._tick()
        except Exception as exc:
            logger.exception("%s tick failed: %s", self.name, exc)
            return
        if ok:
            try:
                self._stamp()
            except Exception as exc:
                logger.exception("%s failed to stamp last_run_at: %s", self.name, exc)

    # --- thread lifecycle ----------------------------------------------
    def _run(self) -> None:
        if self.skip_initial_if_not_due:
            if self._is_due():
                self._run_tick()
            else:
                remaining = self._remaining_seconds()
                if self._stop_event.wait(remaining):
                    return
        else:
            self._run_tick()
        while not self._stop_event.wait(self.interval_seconds):
            self._run_tick()

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._run, daemon=True, name=self.name)
        self.thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
