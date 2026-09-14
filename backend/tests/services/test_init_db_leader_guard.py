"""Tests for init_db leader-guard (hardening #4).

Verifies that ``init_db`` is only called when the worker is the leader,
preventing concurrent Alembic migrations on first boot with multiple workers.
"""

import asyncio
from unittest.mock import MagicMock, patch


def _run_lifespan(app):
    """Run the app's lifespan startup + shutdown synchronously."""
    loop = asyncio.new_event_loop()
    try:

        async def _run():
            async with app.router.lifespan_context(app):
                pass

        loop.run_until_complete(_run())
    finally:
        loop.close()


# Common patches for lifespan dependencies that would hit the real DB or
# start real threads. SessionLocal is patched at the source module so all
# `from .core.database import SessionLocal` imports inside lifespan get the
# mock. Module-level scheduler/downloader objects are replaced with
# MagicMocks so their .start()/.stop() methods are no-ops.
_COMMON_PATCHES = [
    "app.core.database.SessionLocal",
    "app.services.page_protect.resolve_pp_hasher_token",
    "app.services.coraza_config.write_coraza_spoa_config",
    "app.services.certificates.migrate_cert_bundles",
    "app.services.settings.get_setting",
    "app.services.api_armor_profiler.start_profiler",
    "app.services.api_armor_profiler.stop_profiler",
    "app.services.api_armor_schema_learner.start_schema_learner",
    "app.services.api_armor_schema_learner.stop_schema_learner",
    "app.main.acquire_leader_lock",
    "app.main.renew_leader_lock",
    "app.main.release_leader_lock",
    "app.main.start_metrics_sampler",
    "app.main.start_cache_metrics_sampler",
    "app.main.start_mcp_sampler",
    "app.main.start_mcp_catalog_sync",
    "app.main.start_waf_sampler",
    "app.main.start_task_worker",
    "app.main.start_audit_worker",
    "app.main.start_beacon_trust_persist",
    "app.main.seed_beacon_trust_table",
    "app.main.start_page_protect_sampler",
    "app.main.start_page_protect_hasher",
    "app.main._geoip_downloader",
    "app.main._security_list_feed_updater",
    "app.main._rule_set_updater",
    "app.main._auto_renew_scheduler",
]


def _patch_all(leader: bool):
    """Patch all lifespan dependencies. Returns a dict of mocks."""
    mocks = {}
    patchers = []
    for target in _COMMON_PATCHES:
        p = patch(target, new_callable=MagicMock)
        mocks[target] = p.start()
        patchers.append(p)
    mocks["app.main.acquire_leader_lock"].return_value = leader
    mocks["app.main.renew_leader_lock"].return_value = True
    mocks["app.core.database.SessionLocal"].return_value = MagicMock()
    # get_setting returns a string by default
    mocks["app.services.settings.get_setting"].side_effect = lambda db, key, default=None: str(default) if default else "false"
    return mocks, patchers


def test_init_db_called_when_leader():
    """When acquire_leader_lock returns True, init_db must be called."""
    from app.main import app

    with patch("app.main.init_db") as mock_init:
        mocks, patchers = _patch_all(leader=True)
        try:
            _run_lifespan(app)
        finally:
            for p in patchers:
                p.stop()
        mock_init.assert_called_once()


def test_init_db_not_called_when_non_leader():
    """When acquire_leader_lock returns False, init_db must NOT be called —
    the non-leader worker skips migrations and serves HTTP only."""
    from app.main import app

    with patch("app.main.init_db") as mock_init:
        mocks, patchers = _patch_all(leader=False)
        try:
            _run_lifespan(app)
        finally:
            for p in patchers:
                p.stop()
        mock_init.assert_not_called()
        mocks["app.main.start_metrics_sampler"].assert_not_called()
        mocks["app.main.start_task_worker"].assert_not_called()
