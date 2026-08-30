"""API Armor behavioral profiling sampler.

Tails the API Armor profiling log (written by the Rust body_parser module)
and upserts per-endpoint behavioral profiles. Each profile stores the set of
observed normal values across multiple dimensions:

1. Body structure (top-level JSON keys, body depth)
2. GraphQL metrics (operation, depth, complexity, field count, query hash)
3. Content type
4. Auth type
5. Response status codes
6. req_fp full fingerprint
7. Client signals (param keys, param types, header count, path depth)

When a request's dimension values are not in the learned baseline, an anomaly
is recorded (if enforcement mode is active).
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.api_armor import ApiProfile, ApiAnomaly
from .settings import get_setting

logger = logging.getLogger(__name__)
settings = get_settings()


# Dimensions tracked per endpoint
DIMENSIONS = [
    "body_structure",      # top-level JSON keys
    "graphql",             # operation, depth, complexity, query_hash
    "content_type",        # request content type
    "auth_type",           # auth type (jwt, api_key, n)
    "req_fp",              # full request fingerprint
    "req_fp_param_keys",   # parameter key names
    "req_fp_param_types",  # parameter type signature
]


class ApiArmorProfiler:
    """Background thread that tails the API Armor profiling log and upserts profiles."""

    def __init__(self, log_path: Optional[str] = None, sample_interval: float = 5.0):
        self.log_path = log_path or getattr(settings, "API_ARMOR_PROFILING_LOG_PATH", "/app/data/api-armor/profiling.log")
        self.sample_interval = sample_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._offset = 0  # byte offset in the log file

    def start(self) -> None:
        """Start the profiler background thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="api-armor-profiler")
        self._thread.start()
        logger.info("API Armor profiler started (log: %s)", self.log_path)

    def stop(self) -> None:
        """Stop the profiler background thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("API Armor profiler stopped")

    def _run(self) -> None:
        """Main loop: tail the log file and process new lines."""
        while not self._stop_event.is_set():
            try:
                self._process_new_lines()
            except Exception as e:
                logger.error("API Armor profiler error: %s", e)
            self._stop_event.wait(self.sample_interval)

    def _process_new_lines(self) -> int:
        """Read new lines from the log file and process them.

        Returns the number of lines processed.
        """
        if not os.path.exists(self.log_path):
            return 0

        try:
            file_size = os.path.getsize(self.log_path)
        except OSError:
            return 0

        # Handle log rotation (file shrank)
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
                        self._process_entry(entry)
                        count += 1
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.debug("Skipping malformed profiling log line: %s", e)
                self._offset = f.tell()
        except OSError as e:
            logger.error("Error reading profiling log: %s", e)

        return count

    def _process_entry(self, entry: Dict) -> None:
        """Process a single profiling log entry — upsert the endpoint profile."""
        method = entry.get("method", "")
        path = entry.get("path", "")
        if not method or not path:
            return

        # Normalize the path (replace IDs with :id)
        normalized_path = normalize_path(path)

        db = SessionLocal()
        try:
            # Find or create the profile
            profile = (
                db.query(ApiProfile)
                .filter(ApiProfile.method == method)
                .filter(ApiProfile.path == normalized_path)
                .first()
            )

            if not profile:
                profile = ApiProfile(
                    method=method,
                    path=normalized_path,
                    dimensions={},
                    sample_count=0,
                    status_codes={},
                    learned=False,
                )
                db.add(profile)

            # Update dimensions with observed values
            dims = profile.dimensions or {}
            for dim in DIMENSIONS:
                value = extract_dimension(entry, dim)
                if value is not None:
                    if dim not in dims:
                        dims[dim] = {"values": [], "count": 0}
                    dim_data = dims[dim]
                    # Add value if not already seen (cap at 1000 unique values)
                    value_str = json.dumps(value) if not isinstance(value, str) else value
                    if value_str not in dim_data["values"] and len(dim_data["values"]) < 1000:
                        dim_data["values"].append(value_str)
                    dim_data["count"] = dim_data.get("count", 0) + 1

            profile.dimensions = dims
            profile.sample_count = (profile.sample_count or 0) + 1
            profile.last_seen = datetime.now(timezone.utc)

            # Update status codes
            status = entry.get("response_status")
            if status:
                codes = profile.status_codes or {}
                status_str = str(status)
                codes[status_str] = codes.get(status_str, 0) + 1
                profile.status_codes = codes

            # Check for anomalies if profile is learned
            if profile.learned:
                anomaly_dim = check_anomaly(profile, entry)
                if anomaly_dim:
                    anomaly = ApiAnomaly(
                        listener_id=entry.get("listener_id"),
                        method=method,
                        path=normalized_path,
                        dimension=anomaly_dim,
                        observed_value=json.dumps(extract_dimension(entry, anomaly_dim)),
                        expected_values=json.dumps(dims.get(anomaly_dim, {}).get("values", [])),
                        request_id=entry.get("request_id"),
                        client_ip=entry.get("client_ip"),
                    )
                    db.add(anomaly)

            db.commit()
        except Exception as e:
            logger.error("Error processing profiling entry: %s", e)
            db.rollback()
        finally:
            db.close()


def normalize_path(path: str) -> str:
    """Normalize a path by replacing numeric/UUID segments with :id.

    Example: /api/v1/users/123/posts/456 → /api/v1/users/:id/posts/:id
    """
    import re
    # Replace UUIDs first (most specific pattern)
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/:id", path, flags=re.IGNORECASE)
    # Replace hex IDs (24-char MongoDB ObjectIds) before numeric IDs
    path = re.sub(r"/[0-9a-f]{24}", "/:id", path, flags=re.IGNORECASE)
    # Replace numeric IDs last (least specific)
    path = re.sub(r"/\d+", "/:id", path)
    return path


def extract_dimension(entry: Dict, dimension: str) -> Any:
    """Extract a dimension value from a profiling log entry."""
    if dimension == "body_structure":
        bs = entry.get("body_structure")
        if bs and isinstance(bs, dict):
            keys = bs.get("top_keys", [])
            return sorted(keys) if keys else None
        return None
    elif dimension == "graphql":
        gql = entry.get("graphql")
        if gql and isinstance(gql, dict):
            return {
                "operation": gql.get("operation", ""),
                "depth": gql.get("depth", 0),
                "query_hash": gql.get("query_hash", ""),
            }
        return None
    elif dimension == "content_type":
        return entry.get("content_type")
    elif dimension == "auth_type":
        return entry.get("auth_type", "n")
    elif dimension == "req_fp":
        return entry.get("req_fp")
    elif dimension == "req_fp_param_keys":
        return entry.get("req_fp_param_keys")
    elif dimension == "req_fp_param_types":
        return entry.get("req_fp_param_types")
    return None


def check_anomaly(profile: ApiProfile, entry: Dict) -> Optional[str]:
    """Check if a request entry is anomalous compared to the learned profile.

    Returns the dimension name that is anomalous, or None if no anomaly.
    """
    dims = profile.dimensions or {}
    for dim in DIMENSIONS:
        value = extract_dimension(entry, dim)
        if value is None:
            continue
        value_str = json.dumps(value) if not isinstance(value, str) else value
        known_values = dims.get(dim, {}).get("values", [])
        if value_str not in known_values:
            return dim
    return None


def finalize_profile(db: Session, profile_id: int, min_samples: int = 100) -> bool:
    """Mark a profile as learned (baseline confirmed).

    Requires at least min_samples observations.
    Returns True if the profile was finalized.
    """
    profile = db.get(ApiProfile, profile_id)
    if not profile:
        return False
    if (profile.sample_count or 0) < min_samples:
        return False
    profile.learned = True
    db.commit()
    return True


# Singleton instance
_profiler: Optional[ApiArmorProfiler] = None


def start_profiler() -> None:
    """Start the API Armor profiler if enabled."""
    global _profiler
    db = SessionLocal()
    try:
        enabled = get_setting(db, "api_armor_enabled", str(settings.API_ARMOR_ENABLED)).lower() in ("true", "1", "yes")
        profiling_enabled = get_setting(db, "api_armor_profiling_learning_enabled", "false").lower() in ("true", "1", "yes")
        if enabled and profiling_enabled:
            interval = float(get_setting(db, "api_armor_profiler_interval", "5"))
            _profiler = ApiArmorProfiler(sample_interval=interval)
            _profiler.start()
        else:
            logger.info("API Armor profiling not enabled, skipping profiler start")
    finally:
        db.close()


def stop_profiler() -> None:
    """Stop the API Armor profiler if running."""
    global _profiler
    if _profiler:
        _profiler.stop()
        _profiler = None
