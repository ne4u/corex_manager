"""Learners follow API Armor settings without waiting for a process restart."""

import os

from app.services import api_armor_profiler as profiler
from app.services import api_armor_schema_learner as learner
from app.services.api_armor_profiler import ApiArmorProfiler, profiling_log_path
from app.services.api_armor_schema_learner import ApiArmorSchemaLearner
from app.services.settings import get_setting, set_setting


def _stop_learners():
    profiler.stop_profiler()
    learner.stop_schema_learner()


def test_profiling_log_path_uses_profile_setting(monkeypatch, tmp_path):
    """Tailers follow API_ARMOR_PROFILE_LOG_PATH, the same path HAProxy setenv uses."""
    target = tmp_path / "custom" / "profiling.log"
    monkeypatch.setattr(profiler.settings, "API_ARMOR_PROFILE_LOG_PATH", str(target))
    expected = os.path.abspath(str(target))
    assert profiling_log_path() == expected
    assert ApiArmorProfiler().log_path == expected
    assert ApiArmorSchemaLearner().log_path == expected


def test_sync_starts_stops_and_is_idempotent(db, monkeypatch, tmp_path):
    """Saving learning flags starts one tailer each; a second sync does not spawn more."""
    log_path = tmp_path / "api-armor" / "profiling.log"
    monkeypatch.setattr(profiler.settings, "API_ARMOR_PROFILE_LOG_PATH", str(log_path))
    _stop_learners()
    try:
        set_setting(db, "api_armor_enabled", "true")
        set_setting(db, "api_armor_profiling_learning_enabled", "true")
        set_setting(db, "api_armor_schema_learning_enabled", "true")

        profiler.sync_api_armor_learners(db)
        assert profiler._thread_alive(profiler._profiler)
        assert learner._learner is not None and learner._learner._thread is not None
        assert learner._learner._thread.is_alive()
        profiler_thread = profiler._profiler._thread
        learner_thread = learner._learner._thread
        assert log_path.parent.is_dir()
        assert (log_path.parent.stat().st_mode & 0o777) == 0o777
        # The caller-supplied session stays open.
        assert get_setting(db, "api_armor_enabled") == "true"

        profiler.sync_api_armor_learners(db)
        assert profiler._profiler._thread is profiler_thread
        assert learner._learner._thread is learner_thread

        set_setting(db, "api_armor_schema_learning_enabled", "false")
        profiler.sync_api_armor_learners(db)
        assert profiler._profiler._thread is profiler_thread
        assert learner._learner is None

        set_setting(db, "api_armor_enabled", "false")
        profiler.sync_api_armor_learners(db)
        assert profiler._profiler is None
        assert learner._learner is None
    finally:
        _stop_learners()
