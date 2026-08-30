"""Health checker for MCP Gateway.

Periodically pings upstream MCP servers (HTTP and stdio) to determine
health status. Results are stored in Valkey for the backend to read
and include in the config bundle.
"""
import asyncio
import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Health check interval (seconds)
HEALTH_CHECK_INTERVAL = int(os.environ.get("MCP_HEALTH_CHECK_INTERVAL", "30"))

# Health check timeout (seconds)
HEALTH_CHECK_TIMEOUT = int(os.environ.get("MCP_HEALTH_CHECK_TIMEOUT", "10"))

# Valkey key prefix for health status
_HEALTH_KEY_PREFIX = "mcp:health:"


class HealthChecker:
    """Background task that periodically checks upstream server health."""

    def __init__(self, valkey_client=None):
        self._valkey = valkey_client
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def _get_valkey(self):
        if self._valkey:
            return self._valkey
        try:
            from .valkey_client import get_valkey_client
            self._valkey = get_valkey_client()
        except ImportError:
            try:
                from valkey_client import get_valkey_client
                self._valkey = get_valkey_client()
            except Exception:
                pass
        return self._valkey

    async def start(self):
        """Start the health check background loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Health checker started (interval=%ds)", HEALTH_CHECK_INTERVAL)

    async def stop(self):
        """Stop the health check loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Health checker stopped")

    async def _run_loop(self):
        """Main health check loop."""
        while self._running:
            try:
                await self._check_all_servers()
            except Exception as e:
                logger.error("Health check loop error: %s", e)
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)

    async def _check_all_servers(self):
        """Check all enabled servers from the config."""
        try:
            from .config_loader import get_enabled_servers
        except ImportError:
            from config_loader import get_enabled_servers

        servers = get_enabled_servers()
        if not servers:
            return

        tasks = [self._check_server(s) for s in servers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_server(self, server: dict):
        """Check a single server's health and store the result."""
        sid = server.get("id")
        if sid is None:
            return

        transport = server.get("transport_type", "streamable_http")
        status = "unknown"
        error_msg = None

        try:
            if transport == "stdio":
                status, error_msg = await self._check_stdio_server(server)
            else:
                status, error_msg = await self._check_http_server(server)
        except Exception as e:
            status = "unhealthy"
            error_msg = str(e)

        # Store result in Valkey
        health_data = {
            "server_id": sid,
            "status": status,
            "error": error_msg,
            "checked_at": time.time(),
        }
        vk = self._get_valkey()
        if vk:
            try:
                vk.set(f"{_HEALTH_KEY_PREFIX}{sid}", json.dumps(health_data), ex=HEALTH_CHECK_INTERVAL * 3)
            except Exception as e:
                logger.debug("Failed to store health status in Valkey: %s", e)

    async def _check_http_server(self, server: dict) -> tuple[str, Optional[str]]:
        """Check an HTTP/streamable HTTP server via a ping request."""
        url = server.get("url")
        if not url:
            return "unknown", "No URL configured"

        try:
            from .upstream import send_request
        except ImportError:
            from upstream import send_request

        try:
            status_code, body, _ = await asyncio.wait_for(
                send_request(server, {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "ping",
                    "params": {},
                }),
                timeout=HEALTH_CHECK_TIMEOUT,
            )

            if status_code == 200 and isinstance(body, dict):
                if "error" in body:
                    return "unhealthy", f"JSON-RPC error: {body['error']}"
                return "healthy", None
            return "unhealthy", f"HTTP {status_code}"
        except asyncio.TimeoutError:
            return "unhealthy", "Timeout"
        except Exception as e:
            return "unhealthy", str(e)

    async def _check_stdio_server(self, server: dict) -> tuple[str, Optional[str]]:
        """Check a stdio server by verifying the process is alive."""
        try:
            from .stdio_proxy import get_process_manager
        except ImportError:
            from stdio_proxy import get_process_manager

        pm = get_process_manager()
        if pm.is_healthy(server["id"]):
            return "healthy", None
        return "stopped", "Process not running"

    def get_health_status(self, server_id: int) -> dict:
        """Get cached health status for a server (synchronous, from Valkey)."""
        vk = self._get_valkey()
        if not vk:
            return {"status": "unknown", "error": None, "checked_at": 0}
        try:
            data = vk.get(f"{_HEALTH_KEY_PREFIX}{server_id}")
            if data:
                return json.loads(data)
        except Exception:
            pass
        return {"status": "unknown", "error": None, "checked_at": 0}


# Singleton
_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get the singleton HealthChecker."""
    global _checker
    if _checker is None:
        _checker = HealthChecker()
    return _checker
