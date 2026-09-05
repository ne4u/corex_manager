import logging
import socket
import os
from typing import List, Dict, Any
from ..core.config import get_settings
from ..core.valkey_client import cache
from . import dataplane

logger = logging.getLogger(__name__)
settings = get_settings()


def _send_command(cmd: str) -> str:
    path = settings.HAPROXY_SOCKET_PATH
    if not os.path.exists(path):
        logger.warning("HAProxy socket not found at %s", path)
        return ""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(path)
            s.sendall(f"{cmd}\n".encode())
            # Signal we're done writing so HAProxy closes after responding
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            data = b""
            while True:
                try:
                    chunk = s.recv(16384)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode()
    except Exception as e:
        logger.warning("HAProxy socket error for '%s': %s", cmd, e)
        return f"error: {e}"


def _send_command_batch(commands: List[str]) -> str:
    """Send multiple commands to the HAProxy stats socket in a single connection.

    Pipelines all commands (newline-separated) in one socket connection to avoid
    the overhead of opening a new connection per command. Used by the beacon
    trust re-seed to bulk-insert IPs into the stick table after a reload.
    """
    path = settings.HAPROXY_SOCKET_PATH
    if not os.path.exists(path):
        logger.warning("HAProxy socket not found at %s", path)
        return ""
    if not commands:
        return ""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(path)
            # Send all commands at once (newline-separated)
            payload = "\n".join(commands) + "\n"
            s.sendall(payload.encode())
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            data = b""
            while True:
                try:
                    chunk = s.recv(16384)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode()
    except Exception as e:
        logger.warning("HAProxy socket batch error: %s", e)
        return f"error: {e}"


def parse_csv(csv_text: str) -> List[Dict[str, Any]]:
    lines = csv_text.strip().splitlines()
    if not lines:
        return []
    # First line is comment with field names in HAProxy CSV
    header_line = lines[0]
    if header_line.startswith("# "):
        headers = header_line[2:].split(",")
    else:
        headers = lines[0].split(",")
        lines = lines[1:]
    results = []
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        values = line.split(",")
        results.append({h.strip(): v for h, v in zip(headers, values)})
    return results


def _dp_info_to_process_info(info: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Data Plane API info response into the same key/value shape as `show info`."""
    data = info.get("data", info) if isinstance(info, dict) else info
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _compute_cpu_load(info: Dict[str, Any]) -> float:
    # HAProxy reports the percentage of time it was idle; load is the inverse.
    idle = _to_float(info.get("Idle_pct"), 100.0)
    return max(0.0, min(100.0, 100.0 - idle))


def _compute_memory_usage_mb(info: Dict[str, Any]) -> float:
    # Try the most useful memory counters in order of preference.
    for key in ("PoolUsed_MB", "PoolAlloc_MB", "Memmax_MB"):
        val = _to_float(info.get(key), 0.0)
        if val:
            return val
    # Fall back to zlib usage in bytes -> MB.
    zlib = _to_float(info.get("ZlibMemUsage"), 0.0)
    if zlib:
        return zlib / (1024 * 1024)
    return 0.0


@cache(ttl=5, key_prefix="haproxy")
def get_process_info() -> Dict[str, Any]:
    # The Data Plane API /runtime/info endpoint (v3) does not expose Uptime,
    # CurrConns, Maxconn, CumReq, etc. Read the canonical process fields from
    # the local HAProxy socket first, then overlay any extra dataplane fields.
    out = _send_command("show info")
    result: Dict[str, Any] = {}
    for line in out.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip()] = val.strip()

    if settings.DATAPLANE_API_ENABLED:
        try:
            dp_info = dataplane.get_info()
            if isinstance(dp_info, dict) and dp_info.get("status") != "error":
                for k, v in _dp_info_to_process_info(dp_info).items():
                    if k not in result:
                        result[k] = v
        except Exception as exc:
            logger.warning("Data Plane API process info failed: %s", exc)
    return result


@cache(ttl=5, key_prefix="haproxy")
def get_backend_stats() -> List[Dict[str, Any]]:
    if settings.DATAPLANE_API_ENABLED:
        try:
            dp_stats = dataplane.get_stats()
            if dp_stats:
                logger.debug("Using Data Plane API for backend stats")
                return dp_stats
        except Exception as exc:
            logger.warning("Data Plane API backend stats failed, falling back to socket: %s", exc)

    raw = _send_command("show stat")
    return parse_csv(raw)


def _get_dp_stats() -> Dict[str, Any]:
    """Fetch listener/backend stats from the Data Plane API and process info from the HAProxy socket.

    The Data Plane API /runtime/info endpoint does not expose CurrConns/Maxconn/CumReq,
    so we always read those from the local HAProxy socket via get_process_info().
    """
    stats = dataplane.get_stats()
    if not stats:
        return {}
    listeners = [s for s in stats if s.get("type") == "0"]
    backends = [s for s in stats if s.get("type") == "1"]
    info = get_process_info()
    return {
        "process_id": info.get("Pid", 0),
        "cpu_load": _compute_cpu_load(info),
        "memory_usage": _compute_memory_usage_mb(info),
        "current_connections": info.get("CurrConns", 0),
        "max_connections": info.get("Maxconn", 0),
        "total_requests": info.get("CumReq", 0),
        "bytes_in": info.get("CumInBytes", 0),
        "bytes_out": info.get("TotalBytesOut", 0),
        "listeners": listeners,
        "backends": backends,
    }


@cache(ttl=5, key_prefix="haproxy")
def get_stats() -> Dict[str, Any]:
    if settings.DATAPLANE_API_ENABLED:
        dp_stats = _get_dp_stats()
        if dp_stats:
            return dp_stats

    info = get_process_info()
    stats = get_backend_stats()
    listeners = [s for s in stats if s.get("type") == "0"]
    backends = [s for s in stats if s.get("type") == "1"]
    return {
        "process_id": info.get("Pid", 0),
        "cpu_load": _compute_cpu_load(info),
        "memory_usage": _compute_memory_usage_mb(info),
        "current_connections": info.get("CurrConns", 0),
        "max_connections": info.get("Maxconn", 0),
        "total_requests": info.get("CumReq", 0),
        "bytes_in": info.get("CumInBytes", 0),
        "bytes_out": info.get("TotalBytesOut", 0),
        "listeners": listeners,
        "backends": backends,
    }


def _parse_lua_cli_stats(raw: str) -> Dict[str, int]:
    """Parse the output of a Lua CLI stats command.

    The Rust modules register CLI commands (e.g. ``show compress-stats``)
    that print ``key: value`` lines. This parser extracts integer values
    for known keys. Returns an empty dict if the command is not recognized
    (e.g. the module is not loaded).
    """
    result: Dict[str, int] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace("-", "_").replace(" ", "_")
            try:
                result[key] = int(val.strip())
            except (TypeError, ValueError):
                continue
    return result


def get_lua_module_stats() -> Dict[str, Any]:
    """Fetch cumulative bytes-saved counters from the Rust Lua modules.

    The haproxy-compression (brotli/zstd) and haproxy-img-2-webp modules
    each register a CLI command that returns their global AtomicU64 counter:

    - ``show compress-stats`` → ``bytes_saved: <N>`` (brotli/zstd compression)
    - ``show webp-stats`` → ``bytes_saved: <N>`` (WebP image conversion)

    These are only available when the respective modules are loaded (i.e.
    when compression or img_2_webp is enabled in Global Options). If a
    command is not recognized, the counter defaults to 0.

    Returns ``{"brotli_zstd_bytes_saved": int, "webp_bytes_saved": int}``.
    """
    result = {"brotli_zstd_bytes_saved": 0, "webp_bytes_saved": 0}

    # Compression (brotli/zstd) — only available when the compression module
    # is loaded (compression_enabled in Global Options). When the module is
    # not loaded, HAProxy returns an "Unknown command" error.
    raw = _send_command("show compress-stats")
    if raw and "bytes_saved:" in raw:
        parsed = _parse_lua_cli_stats(raw)
        result["brotli_zstd_bytes_saved"] = parsed.get("bytes_saved", 0)
    elif raw:
        logger.debug("compress-stats CLI not available: %s", raw.strip()[:100])

    # WebP image conversion — only available when the img_2_webp module is
    # loaded (img_2_webp_enabled in Global Options).
    raw = _send_command("show webp-stats")
    if raw and "bytes_saved:" in raw:
        parsed = _parse_lua_cli_stats(raw)
        result["webp_bytes_saved"] = parsed.get("bytes_saved", 0)
    elif raw:
        logger.debug("webp-stats CLI not available: %s", raw.strip()[:100])

    return result
