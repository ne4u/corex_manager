"""Dynamic feed updater for Security Lists.

A background thread polls enabled DynamicFeed rows and refreshes the ones that
are due (based on update_interval_hours). Each refresh fetches the feed URL,
parses the response, validates entries per list_type, and replaces the target
list's entries.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.models import (
    AsnList,
    AsnListEntry,
    DynamicFeed,
    Ja4List,
    Ja4ListEntry,
    NetworkList,
    NetworkListEntry,
)
from .scheduler import PeriodicTask
from .security_lists import parse_feed_text, validate_asn_value, validate_ja4_value, validate_network_value

logger = logging.getLogger(__name__)
settings = get_settings()


def _utcnow() -> datetime:
    """Return current UTC time as a naive datetime.

    SQLite does not preserve timezone info, so stored datetimes come back
    as offset-naive. Using naive UTC here ensures comparisons like
    (now - feed.last_updated_at) don't fail with "can't subtract
    offset-naive and offset-aware datetimes".
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def refresh_feed(db: Session, feed: DynamicFeed) -> Dict[str, Any]:
    """Fetch and apply a single feed. Mutates the target list's entries.

    Returns a summary dict: {ok, entry_count, skipped, error?}.
    """
    try:
        resp = requests.get(feed.url, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as exc:
        feed.last_error = str(exc)
        db.commit()
        return {"ok": False, "entry_count": 0, "skipped": 0, "error": str(exc)}

    raw_rows = parse_feed_text(resp.text, list_type=feed.list_type)

    if feed.list_type == "network":
        target = db.get(NetworkList, feed.target_list_id)
        entry_cls = NetworkListEntry
        validator = validate_network_value
    elif feed.list_type == "asn":
        target = db.get(AsnList, feed.target_list_id)
        entry_cls = AsnListEntry
        validator = validate_asn_value
    elif feed.list_type == "ja4":
        target = db.get(Ja4List, feed.target_list_id)
        entry_cls = Ja4ListEntry
        validator = validate_ja4_value
    else:
        feed.last_error = f"Unknown list_type: {feed.list_type}"
        db.commit()
        return {"ok": False, "entry_count": 0, "skipped": 0, "error": feed.last_error}

    if not target:
        feed.last_error = f"Target list {feed.target_list_id} not found"
        db.commit()
        return {"ok": False, "entry_count": 0, "skipped": 0, "error": feed.last_error}

    validated: list = []
    skipped = 0
    seen: set = set()
    for token, note in raw_rows:
        try:
            v = validator(token)
        except ValueError:
            skipped += 1
            continue
        if v in seen:
            continue
        seen.add(v)
        validated.append((v, note))

    # Detect whether the feed actually changed the list contents so we only
    # auto-apply when a real diff is produced (avoids needless reloads when a
    # feed returns the same entries it already had).
    old_values = sorted(e.value for e in target.entries)
    new_values = sorted(v for v, _ in validated)
    changed = old_values != new_values

    # Replace entries.
    db.query(entry_cls).filter(entry_cls.list_id == target.id).delete()
    for v, note in validated:
        db.add(entry_cls(list_id=target.id, value=v, note=note))

    feed.last_error = None
    feed.last_entry_count = len(validated)
    feed.last_updated_at = _utcnow()
    target.updated_at = _utcnow()
    db.commit()

    if changed:
        _maybe_auto_apply_after_feed_refresh(db)

    return {"ok": True, "entry_count": len(validated), "skipped": skipped, "changed": changed}


class DynamicFeedUpdater(PeriodicTask):
    """Background thread that refreshes due DynamicFeeds on a poll interval.

    Restart-safe: skips the immediate poll on startup when a poll was recently
    completed (within ``poll_interval_seconds``). The per-feed freshness check
    in ``_refresh_due_feeds`` prevents redundant feed fetches regardless.
    """

    def __init__(self, poll_interval_seconds: Optional[int] = None):
        super().__init__(
            name="security_list_feeds_poll",
            interval_seconds=(
                poll_interval_seconds
                if poll_interval_seconds is not None
                else settings.SECURITY_LISTS_FEED_POLL_INTERVAL_SECONDS
            ),
        )

    def _tick(self) -> bool:
        try:
            with SessionLocal() as db:
                self._refresh_due_feeds(db)
        except Exception as exc:
            logger.exception("Dynamic feed update tick failed: %s", exc)
            return False
        return True

    def _refresh_due_feeds(self, db: Session):
        now = _utcnow()
        feeds = db.query(DynamicFeed).filter(DynamicFeed.enabled == True).all()  # noqa: E712
        for feed in feeds:
            if not feed.url:
                continue
            due = (
                feed.last_updated_at is None
                or (now - feed.last_updated_at).total_seconds()
                >= feed.update_interval_hours * 3600
            )
            if not due:
                continue
            try:
                result = refresh_feed(db, feed)
                if result.get("ok"):
                    logger.info(
                        "Feed '%s' refreshed: %d entries (%d skipped)",
                        feed.name,
                        result["entry_count"],
                        result["skipped"],
                    )
                else:
                    logger.warning(
                        "Feed '%s' refresh failed: %s",
                        feed.name,
                        result.get("error"),
                    )
            except Exception as exc:
                logger.exception("Error refreshing feed '%s': %s", feed.name, exc)
                try:
                    feed.last_error = str(exc)
                    feed.last_updated_at = now
                    db.commit()
                except Exception:
                    db.rollback()


def _maybe_auto_apply_after_feed_refresh(db: Session) -> None:
    """Auto-apply config after a feed refresh produced a content change.

    Only fires when the *sole* pending changes are security list files —
    unrelated pending config edits (backends, listeners, WAF rules, …) are
    never swept up by an automatic apply. If other pending changes exist, the
    feed's list changes remain pending until the user applies manually.
    """
    try:
        from .config import security_list_files_unapplied
        from .tasks import queue_task
        sec_unapplied, other_unapplied = security_list_files_unapplied(db)
        if not sec_unapplied:
            return
        if other_unapplied:
            logger.info(
                "Feed refresh produced security-list changes but other pending "
                "config changes exist; skipping auto-apply."
            )
            return
        task_id = queue_task(
            "apply_config",
            payload={
                "created_by": "system",
                "comment": "Auto-apply: security list feed refresh",
            },
        )
        logger.info("Feed refresh auto-applied config (task %s)", task_id)
    except Exception as exc:
        logger.warning("Auto-apply after feed refresh failed: %s", exc)
