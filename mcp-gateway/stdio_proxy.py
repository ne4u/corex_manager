"""stdio process manager for MCP Gateway.

Manages subprocess MCP servers that communicate via stdin/stdout JSON-RPC.
Each stdio server is spawned as a child process; requests are written to stdin
and responses are read from stdout. The process manager handles:
- Process lifecycle (start, stop, restart)
- Request/response correlation via JSON-RPC id
- Health checking (process alive)
- Graceful shutdown
"""
import asyncio
import json
import logging
import os
import signal
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Request timeout for stdio responses (seconds)
_STDIO_TIMEOUT = int(os.environ.get("MCP_STDIO_TIMEOUT", "30"))

# Idle timeout: stop process after this many seconds without requests (0 = never)
_STDIO_IDLE_TIMEOUT = int(os.environ.get("MCP_STDIO_IDLE_TIMEOUT", "600"))


class StdioProcess:
    """Wraps a single stdio MCP server subprocess."""

    def __init__(self, server_id: int, command: str, args: list[str], env: dict[str, str]):
        self.server_id = server_id
        self.command = command
        self.args = args
        self.env = env
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._next_id: int = 1
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._last_activity: float = time.time()
        self._initialized: bool = False
        self._init_lock = asyncio.Lock()

    async def start(self) -> bool:
        """Spawn the subprocess."""
        if self._proc and self._proc.returncode is None:
            return True  # already running

        try:
            full_env = dict(os.environ)
            full_env.update(self.env)
            self._proc = await asyncio.create_subprocess_exec(
                self.command,
                *self.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=full_env,
            )
            self._last_activity = time.time()
            self._initialized = False
            self._reader_task = asyncio.create_task(self._read_loop())
            logger.info("Started stdio process for server %d: %s %s (pid=%d)",
                        self.server_id, self.command, " ".join(self.args), self._proc.pid)
            return True
        except Exception as e:
            logger.error("Failed to start stdio process for server %d: %s", self.server_id, e)
            self._proc = None
            return False

    async def stop(self) -> None:
        """Stop the subprocess gracefully."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._proc and self._proc.returncode is None:
            try:
                self._proc.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self._proc.kill()
                    await self._proc.wait()
                logger.info("Stopped stdio process for server %d", self.server_id)
            except Exception as e:
                logger.warning("Error stopping stdio process for server %d: %s", self.server_id, e)

        # Cancel any pending futures
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(RuntimeError("Process stopped"))
        self._pending.clear()
        self._proc = None
        self._initialized = False

    async def restart(self) -> bool:
        """Restart the subprocess."""
        await self.stop()
        return await self.start()

    def is_running(self) -> bool:
        """Check if the process is alive."""
        return self._proc is not None and self._proc.returncode is None

    def is_idle(self) -> bool:
        """Check if the process has been idle longer than the idle timeout."""
        if _STDIO_IDLE_TIMEOUT <= 0:
            return False
        return (time.time() - self._last_activity) > _STDIO_IDLE_TIMEOUT

    async def _read_loop(self) -> None:
        """Continuously read JSON-RPC responses from stdout."""
        if not self._proc or not self._proc.stdout:
            return
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    break
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue
                try:
                    msg = json.loads(line_str)
                except json.JSONDecodeError:
                    logger.debug("stdio server %d: non-JSON stdout: %s", self.server_id, line_str[:200])
                    continue

                # Correlate by id
                msg_id = msg.get("id")
                if msg_id is not None and msg_id in self._pending:
                    fut = self._pending.pop(msg_id)
                    if not fut.done():
                        fut.set_result(msg)
                # Notifications (no id) are logged but not handled
                elif "method" in msg:
                    logger.debug("stdio server %d: notification: %s", self.server_id, msg.get("method"))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("stdio read loop error for server %d: %s", self.server_id, e)
        finally:
            # Process ended — cancel pending futures
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("stdio process exited unexpectedly"))
            self._pending.clear()
            self._initialized = False

    async def send_request(self, message: dict) -> dict:
        """Send a JSON-RPC request to the subprocess and await the response.

        The message's 'id' will be overridden with an internal counter for
        correlation. The original id is restored in the response.
        """
        if not self.is_running():
            ok = await self.start()
            if not ok:
                return {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Failed to start stdio process"}}

        if not self._proc or not self._proc.stdin:
            return {"jsonrpc": "2.0", "error": {"code": -32000, "message": "stdio process stdin not available"}}

        self._last_activity = time.time()
        original_id = message.get("id")
        internal_id = self._next_id
        self._next_id += 1
        message["id"] = internal_id

        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[internal_id] = fut

        try:
            data = (json.dumps(message) + "\n").encode("utf-8")
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()
        except Exception as e:
            self._pending.pop(internal_id, None)
            return {"jsonrpc": "2.0", "error": {"code": -32000, "message": f"Failed to write to stdin: {e}"}}

        try:
            response = await asyncio.wait_for(fut, timeout=_STDIO_TIMEOUT)
            response["id"] = original_id
            return response
        except asyncio.TimeoutError:
            self._pending.pop(internal_id, None)
            return {"jsonrpc": "2.0", "id": original_id, "error": {"code": -32000, "message": "stdio request timeout"}}
        except Exception as e:
            self._pending.pop(internal_id, None)
            return {"jsonrpc": "2.0", "id": original_id, "error": {"code": -32000, "message": f"stdio error: {e}"}}

    async def send_notification(self, message: dict) -> int:
        """Send a JSON-RPC notification (no response expected). Returns 0 on success."""
        if not self.is_running():
            return 502
        if not self._proc or not self._proc.stdin:
            return 502

        self._last_activity = time.time()
        try:
            data = (json.dumps(message) + "\n").encode("utf-8")
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()
            return 200
        except Exception as e:
            logger.error("stdio notification failed for server %d: %s", self.server_id, e)
            return 502

    async def initialize(self) -> Optional[str]:
        """Send initialize request and return a synthetic session ID."""
        async with self._init_lock:
            if self._initialized:
                return f"stdio:{self.server_id}"

            resp = await self.send_request({
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": "0.1.0"},
                },
            })
            if "error" in resp:
                logger.error("stdio initialize failed for server %d: %s", self.server_id, resp["error"])
                return None

            # Send initialized notification
            await self.send_notification({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            })
            self._initialized = True
            return f"stdio:{self.server_id}"

    async def fetch_catalog(self) -> Optional[dict]:
        """Fetch tools/list, resources/list, prompts/list from the stdio server."""
        catalog: dict[str, list] = {"tools": [], "resources": [], "prompts": []}

        for method, key in [
            ("tools/list", "tools"),
            ("resources/list", "resources"),
            ("prompts/list", "prompts"),
        ]:
            resp = await self.send_request({
                "jsonrpc": "2.0",
                "method": method,
                "params": {},
            })
            if "result" in resp and key in resp["result"]:
                items = resp["result"][key]
                # Handle pagination cursor if present
                while resp.get("result", {}).get("nextCursor"):
                    resp = await self.send_request({
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": {"cursor": resp["result"]["nextCursor"]},
                    })
                    if "result" in resp and key in resp["result"]:
                        items.extend(resp["result"][key])
                    else:
                        break
                catalog[key] = items
            elif "error" in resp:
                logger.debug("stdio catalog %s for server %d: %s", method, self.server_id, resp["error"])

        return catalog


class ProcessManager:
    """Singleton managing all stdio MCP server processes."""

    def __init__(self):
        self._processes: dict[int, StdioProcess] = {}
        self._lock = asyncio.Lock()

    async def get_process(self, server: dict) -> Optional[StdioProcess]:
        """Get or create a StdioProcess for a server config."""
        sid = server["id"]
        if server.get("transport_type") != "stdio":
            return None

        async with self._lock:
            if sid in self._processes:
                proc = self._processes[sid]
                if proc.is_running():
                    return proc
                # Process died — restart
                if not await proc.start():
                    return None
                return proc

            # Create new process
            command = server.get("command")
            if not command:
                logger.error("stdio server %d: no command specified", sid)
                return None

            args = server.get("args", [])
            env = server.get("env_vars", {})
            proc = StdioProcess(sid, command, args, env)
            if not await proc.start():
                return None
            self._processes[sid] = proc
            return proc

    async def send_request(self, server: dict, message: dict) -> tuple[int, dict, dict]:
        """Send a JSON-RPC request to a stdio server. Returns (status, body, headers)."""
        proc = await self.get_process(server)
        if not proc:
            return 502, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "No stdio process available"}}, {}
        response = await proc.send_request(message)
        return 200, response, {}

    async def send_notification(self, server: dict, message: dict) -> int:
        """Send a notification to a stdio server."""
        proc = await self.get_process(server)
        if not proc:
            return 502
        return await proc.send_notification(message)

    async def initialize_upstream(self, server: dict) -> Optional[str]:
        """Initialize a stdio upstream session."""
        proc = await self.get_process(server)
        if not proc:
            return None
        return await proc.initialize()

    async def fetch_catalog(self, server: dict) -> Optional[dict]:
        """Fetch catalog from a stdio server."""
        proc = await self.get_process(server)
        if not proc:
            return None
        return await proc.fetch_catalog()

    async def stop_server(self, server_id: int) -> None:
        """Stop and remove a server's process."""
        async with self._lock:
            proc = self._processes.pop(server_id, None)
        if proc:
            await proc.stop()

    async def restart_server(self, server_id: int) -> bool:
        """Restart a server's process."""
        proc = self._processes.get(server_id)
        if proc:
            return await proc.restart()
        return False

    def is_healthy(self, server_id: int) -> bool:
        """Check if a server's process is alive."""
        proc = self._processes.get(server_id)
        return proc.is_running() if proc else False

    async def stop_idle_processes(self) -> None:
        """Stop processes that have been idle too long."""
        to_stop = [sid for sid, proc in self._processes.items() if proc.is_idle()]
        for sid in to_stop:
            logger.info("Stopping idle stdio process for server %d", sid)
            await self.stop_server(sid)

    async def shutdown_all(self) -> None:
        """Stop all processes on gateway shutdown."""
        async with self._lock:
            processes = list(self._processes.values())
            self._processes.clear()
        for proc in processes:
            await proc.stop()
        logger.info("All stdio processes stopped")


# Singleton
_manager: Optional[ProcessManager] = None


def get_process_manager() -> ProcessManager:
    """Get the singleton ProcessManager."""
    global _manager
    if _manager is None:
        _manager = ProcessManager()
    return _manager
