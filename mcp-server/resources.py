"""Curated read-only MCP resources — each maps to a backend GET endpoint.

Resources are fetched in-process via the same ASGI transport as tools.
"""
import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Each resource: (uri, name, description, backend_path, mime_type)
_RESOURCES = [
    {
        "uri": "corex://config/preview",
        "name": "config-preview",
        "description": "Preview the generated HAProxy config without applying it.",
        "path": "/api/v1/config/preview",
        "mimeType": "text/plain",
    },
    {
        "uri": "corex://config/status",
        "name": "config-status",
        "description": "Current config apply status (applied vs pending changes).",
        "path": "/api/v1/config/status",
        "mimeType": "application/json",
    },
    {
        "uri": "corex://config/snapshots",
        "name": "config-snapshots",
        "description": "List of config snapshots (applied config history).",
        "path": "/api/v1/config/snapshots",
        "mimeType": "application/json",
    },
    {
        "uri": "corex://system/stats",
        "name": "system-stats",
        "description": "System stats (HAProxy process info, uptime, connections).",
        "path": "/api/v1/stats",
        "mimeType": "application/json",
    },
    {
        "uri": "corex://system/haproxy-stats",
        "name": "haproxy-stats",
        "description": "HAProxy stats (frontend/backend/server metrics).",
        "path": "/api/v1/haproxy-stats",
        "mimeType": "application/json",
    },
    {
        "uri": "corex://audit-events",
        "name": "audit-events",
        "description": "Recent audit events (config mutations, auth events).",
        "path": "/api/v1/audit-events",
        "mimeType": "application/json",
    },
    {
        "uri": "corex://health",
        "name": "health",
        "description": "Backend health check.",
        "path": "/api/v1/health",
        "mimeType": "application/json",
    },
]


def list_resources() -> list[dict]:
    """Return MCP resource descriptors for resources/list."""
    return [
        {
            "uri": r["uri"],
            "name": r["name"],
            "description": r["description"],
            "mimeType": r["mimeType"],
        }
        for r in _RESOURCES
    ]


async def read_resource(uri: str) -> Optional[dict]:
    """Read a resource by URI. Returns the MCP resource-read result or None."""
    res = next((r for r in _RESOURCES if r["uri"] == uri), None)
    if not res:
        return None

    try:
        from .tools import _get_client, _get_service_jwt, _get_service_token
    except ImportError:
        from tools import _get_client, _get_service_jwt, _get_service_token

    client = _get_client()
    headers = {"Authorization": f"Bearer {_get_service_jwt()}"}
    service_token = _get_service_token()
    if service_token:
        headers["X-MCP-Service-Token"] = service_token

    try:
        resp = await client.get(res["path"], headers=headers)
    except Exception as e:
        logger.exception("Resource read failed: %s", uri)
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "text/plain",
                    "text": f"Error reading resource: {e}",
                }
            ]
        }

    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            text = json.dumps(resp.json(), indent=2, default=str)
        except Exception:
            text = resp.text
    else:
        text = resp.text

    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": res["mimeType"],
                "text": text,
            }
        ]
    }
