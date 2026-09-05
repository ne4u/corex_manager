"""Beacon Trust persistence — exports the beacon_trust_table stick table to Valkey
and re-seeds it after HAProxy reloads.

HAProxy stick tables are lost on every reload (which happens on every config
apply). This service periodically exports the trusted IPs to Valkey so they
can be restored after a reload.

Two functions:
- ``export_trust_table()`` — reads ``show table beacon_trust_table`` from the
  HAProxy stats socket, parses the trusted IPs, and stores them in Valkey.
  Called periodically by the background thread.
- ``seed_beacon_trust_table()`` — reads the trusted IPs from Valkey and sends
  ``set table beacon_trust_table key <ip> data.cnt 1`` for each IP via the
  stats socket (batched in a single connection). Called after every successful
  HAProxy reload and once on startup.
"""
import json
import logging
import threading
import time
from typing import List

from ..core.config import get_settings
from ..core import valkey_client

logger = logging.getLogger(__name__)
settings = get_settings()

VALKEY_KEY = "beacon_trust:ips"


def _parse_show_table(output: str) -> List[str]:
    """Parse the output of ``show table beacon_trust_table`` and return trusted IPs.

    Output format (one entry per line):
        0x7f...: key=192.168.1.5 use=0 exp=45000 ...

    Returns the list of IP addresses (keys) from all entries. Any key present
    in the table was put there by track-sc4, which means the IP was beacon-
    trusted. We don't check gpt0 because track-sc doesn't set it; we use
    table_cnt (request count) for runtime lookups instead.
    """
    ips: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("table:"):
            continue
        # Extract key=<ip>
        for field in line.split():
            if field.startswith("key="):
                ips.append(field[4:])
                break
    return ips


def export_trust_table() -> List[str]:
    """Export the beacon_trust_table stick table to Valkey.

    Sends ``show table beacon_trust_table`` to the HAProxy stats socket,
    parses the trusted IPs, and stores them in Valkey as a JSON list.

    Returns the list of trusted IPs (for testing/logging).
    """
    from . import stats

    output = stats._send_command("show table beacon_trust_table")
    if not output or output.startswith("error:"):
        logger.debug("beacon_trust export: no table output or error")
        return []

    ips = _parse_show_table(output)
    if not ips:
        logger.debug("beacon_trust export: no trusted IPs in table")
        return []

    # Store in Valkey with a TTL slightly longer than the trust TTL + export
    # interval so the snapshot survives between exports.
    trust_ttl = getattr(settings, "BEACON_TRUST_TTL_SECONDS", 900)
    persist_interval = getattr(settings, "BEACON_TRUST_PERSIST_INTERVAL_SECONDS", 60)
    valkey_ttl = trust_ttl + persist_interval + 120
    valkey_client.cache_set(VALKEY_KEY, ips, ttl=valkey_ttl)
    logger.debug("beacon_trust export: stored %d trusted IPs in Valkey", len(ips))
    return ips


def seed_beacon_trust_table() -> int:
    """Re-seed the beacon_trust_table stick table from Valkey after a reload.

    Reads the trusted IPs from Valkey and sends ``set table`` commands via
    the stats socket (batched in a single connection for efficiency).

    Returns the number of IPs re-seeded.
    """
    from . import stats

    ips = valkey_client.cache_get(VALKEY_KEY)
    if not ips or not isinstance(ips, list):
        logger.debug("beacon_trust re-seed: no IPs in Valkey")
        return 0

    # Build batch commands: one "set table" per IP. We set data.http_req_cnt 1
    # so table_http_req_cnt(beacon_trust_table) returns >= 1 for re-seeded IPs,
    # matching the runtime check used by the sliding-window refresh and the
    # ip.beacon_trusted risk-scoring field.
    commands = [f"set table beacon_trust_table key {ip} data.http_req_cnt 1" for ip in ips]
    result = stats._send_command_batch(commands)
    if result.startswith("error:"):
        logger.warning("beacon_trust re-seed: socket error: %s", result)
        return 0

    logger.info("beacon_trust re-seed: restored %d trusted IPs", len(ips))
    return len(ips)


def _persist_loop() -> None:
    """Background loop that exports the trust table to Valkey periodically."""
    while True:
        try:
            time.sleep(settings.BEACON_TRUST_PERSIST_INTERVAL_SECONDS)
            export_trust_table()
        except Exception as exc:
            logger.exception("beacon_trust persist loop error: %s", exc)


def start_beacon_trust_persist() -> None:
    """Start the background persistence thread."""
    thread = threading.Thread(target=_persist_loop, daemon=True)
    thread.start()
    logger.info("beacon_trust persist thread started")
