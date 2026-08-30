"""Remote rule set downloader for WAF rules.

A background thread polls enabled WafRules with rule_set == "remote" and
downloads the .conf file from the configured URL. The file is verified against
an optional SHA256 hash and written to the shared volume for the coraza-spoa
container to include.
"""
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.models import WafRule
from .scheduler import PeriodicTask

logger = logging.getLogger(__name__)
settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _rule_file_path(rule_name: str) -> str:
    """Return the absolute filesystem path for a rule's downloaded .conf file."""
    safe_name = "".join(c for c in rule_name if c.isalnum() or c in "-_") or "rule"
    return os.path.join(os.path.abspath(settings.CUSTOM_RULES_DIR), f"{safe_name}.conf")


def _coraza_include_path(rule_name: str) -> str:
    """Return the path as seen from inside the coraza-spoa container."""
    safe_name = "".join(c for c in rule_name if c.isalnum() or c in "-_") or "rule"
    return f"/app/data/custom-rules/{safe_name}.conf"


def download_rule_set(db: Session, rule: WafRule) -> bool:
    """Download a single rule set from its URL. Returns True on success.

    On success: writes the file, updates rule_set_last_updated_at, clears error.
    On failure: sets rule_set_last_error, keeps the old file if it exists.
    """
    if not rule.rule_set_url:
        rule.rule_set_last_error = "No URL configured"
        db.commit()
        return False

    try:
        resp = requests.get(rule.rule_set_url, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as exc:
        rule.rule_set_last_error = str(exc)
        db.commit()
        logger.warning("Failed to download rule set for '%s': %s", rule.name, exc)
        return False

    content = resp.text

    # Verify SHA256 if configured
    if rule.rule_set_sha256:
        actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if actual.lower() != rule.rule_set_sha256.lower():
            rule.rule_set_last_error = f"SHA256 mismatch: expected {rule.rule_set_sha256}, got {actual}"
            db.commit()
            logger.warning("SHA256 mismatch for rule set '%s'", rule.name)
            return False

    # Write to the shared volume
    path = _rule_file_path(rule.name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    rule.rule_set_last_updated_at = _utcnow().replace(tzinfo=None)
    rule.rule_set_last_error = None
    db.commit()
    logger.info("Downloaded rule set for '%s' to %s", rule.name, path)
    return True


class RuleSetUpdater(PeriodicTask):
    """Background thread that downloads and auto-updates remote rule sets.

    Restart-safe: skips the immediate poll on startup when a poll was recently
    completed (within ``poll_interval_seconds``). The per-rule freshness check
    in ``_update_due_rules`` prevents redundant rule-set downloads regardless.
    """

    def __init__(self, poll_interval_seconds: Optional[int] = None):
        super().__init__(
            name="rule_set_download_poll",
            interval_seconds=(
                poll_interval_seconds
                if poll_interval_seconds is not None
                else settings.RULE_SET_DOWNLOAD_INTERVAL_SECONDS
            ),
        )

    def _tick(self) -> bool:
        try:
            with SessionLocal() as db:
                self._update_due_rules(db)
        except Exception as exc:
            logger.exception("Rule set update tick failed: %s", exc)
            return False
        return True

    def _update_due_rules(self, db: Session):
        now = _utcnow()
        rules = db.query(WafRule).filter(
            WafRule.enabled == True,  # noqa: E712
            WafRule.rule_set == "remote",
            WafRule.rule_set_url.isnot(None),
        ).all()

        changed = False
        for rule in rules:
            file_exists = os.path.exists(_rule_file_path(rule.name))
            if not file_exists:
                # First download
                if download_rule_set(db, rule):
                    changed = True
                continue

            if not rule.rule_set_auto_update:
                continue

            # Check if auto-update is due
            interval = rule.rule_set_update_interval_hours or 24
            last = rule.rule_set_last_updated_at
            if last is None:
                due = True
            else:
                # last is naive UTC; compare with naive UTC now
                now_naive = now.replace(tzinfo=None)
                due = (now_naive - last).total_seconds() >= interval * 3600

            if due:
                if download_rule_set(db, rule):
                    changed = True

        if changed:
            # Regenerate Coraza config to pick up the new Include
            from . import coraza_config
            coraza_config.write_coraza_spoa_config(db)
