"""API Armor schema-learning sampler.

Tails the same profiling log as the profiler and, when schema learning is
enabled, merges observed request bodies ("body_sample") into per-endpoint
learned JSON Schemas. It also prunes old learned schemas by retention.
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.api_armor import ApiSchema
from .api_armor_schemas import merge_learned_schema
from .settings import get_setting

logger = logging.getLogger(__name__)
settings = get_settings()

# Default cap on body sample size to avoid storing huge payloads.
_MAX_BODY_SAMPLE_SIZE = 4096


class ApiArmorSchemaLearner:
    """Background thread that tails the profiling log and learns schemas."""

    def __init__(self, log_path: Optional[str] = None, sample_interval: float = 5.0):
        self.log_path = log_path or getattr(settings, "API_ARMOR_PROFILING_LOG_PATH", "/app/data/api-armor/profiling.log")
        self.sample_interval = sample_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._offset = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="api-armor-schema-learner")
        self._thread.start()
        logger.info("API Armor schema learner started (log: %s)", self.log_path)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("API Armor schema learner stopped")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._process_new_lines()
                self._prune_old_schemas()
            except Exception as e:
                logger.error("API Armor schema learner error: %s", e)
            self._stop_event.wait(self.sample_interval)

    def _process_new_lines(self) -> int:
        if not os.path.exists(self.log_path):
            return 0

        try:
            file_size = os.path.getsize(self.log_path)
        except OSError:
            return 0

        # Handle log rotation.
        if file_size < self._offset:
            self._offset = 0

        if file_size == self._offset:
            return 0

        count = 0
        try:
            with open(self.log_path, "r") as f:
                f.seek(self._offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        ingest_schema_learning_entry_from_log(entry)
                        count += 1
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.debug("Skipping malformed schema-learning log line: %s", e)
                self._offset = f.tell()
        except OSError as e:
            logger.error("Error reading profiling log for schema learning: %s", e)

        return count

    def _prune_old_schemas(self) -> None:
        db = SessionLocal()
        try:
            retention_days = getattr(settings, "API_ARMOR_SCHEMA_LEARN_RETENTION_DAYS", 30)
            prune_learned_schemas(db, retention_days)
            db.commit()
        except Exception as e:
            logger.error("Error pruning learned schemas: %s", e)
            db.rollback()
        finally:
            db.close()


def ingest_schema_learning_entry_from_log(entry: Dict[str, Any]) -> None:
    """Ingest a single profiling log entry for schema learning.

    Expects `method` and `path`, and either `body_sample` (raw body JSON) or
    `graphql` (a parsed GraphQL query dict) to derive a schema.  Body samples
    are truncated before storage to avoid leaking large payloads.
    """
    method = entry.get("method", "")
    path = entry.get("path", "")
    if not method or not path:
        return

    body = entry.get("body_sample")
    if body is None:
        # Fall back to graphql structure if this is a GraphQL request.
        graphql = entry.get("graphql")
        if graphql and isinstance(graphql, dict):
            # GraphQL variables are a natural JSON schema target.
            body = graphql.get("variables") or graphql
        else:
            # Nothing to learn from.
            return

    if not isinstance(body, dict):
        # For now, only object bodies are learned.
        return

    db = SessionLocal()
    try:
        # Truncate body before learning to bound schema size/privacy.
        body = _truncate_body_sample(body)
        merge_learned_schema(db, method, path, body)
        db.commit()
    except Exception as e:
        logger.error("Error merging learned schema: %s", e)
        db.rollback()
    finally:
        db.close()


def _truncate_body_sample(body: Any) -> Any:
    """Truncate string values in a body sample to avoid huge payloads."""
    if isinstance(body, dict):
        out = {}
        for k, v in body.items():
            if isinstance(v, str) and len(v) > _MAX_BODY_SAMPLE_SIZE:
                out[k] = v[:_MAX_BODY_SAMPLE_SIZE]
            else:
                out[k] = _truncate_body_sample(v)
        return out
    if isinstance(body, list):
        # Only keep the first item for schema inference to keep samples small.
        if not body:
            return []
        return [_truncate_body_sample(body[0])]
    return body


def prune_learned_schemas(db: Session, retention_days: int) -> int:
    """Delete learned schemas older than the configured retention."""
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    count = (
        db.query(ApiSchema)
        .filter(ApiSchema.source == "learned")
        .filter(ApiSchema.created_at < cutoff)
        .delete()
    )
    return count


# Singleton management
_learner: Optional[ApiArmorSchemaLearner] = None


def start_schema_learner() -> None:
    """Start the API Armor schema learner if globally enabled."""
    global _learner
    if _learner:
        return

    db = SessionLocal()
    try:
        enabled = get_setting(db, "api_armor_enabled", str(settings.API_ARMOR_ENABLED)).lower() in ("true", "1", "yes")
        learning_enabled = get_setting(db, "api_armor_schema_learning_enabled", "false").lower() in ("true", "1", "yes")
        if enabled and learning_enabled:
            interval = float(get_setting(db, "api_armor_schema_learn_interval", "30"))
            _learner = ApiArmorSchemaLearner(sample_interval=interval)
            _learner.start()
        else:
            logger.info("API Armor schema learning not enabled, skipping learner start")
    finally:
        db.close()


def stop_schema_learner() -> None:
    """Stop the API Armor schema learner if running."""
    global _learner
    if _learner:
        _learner.stop()
        _learner = None
