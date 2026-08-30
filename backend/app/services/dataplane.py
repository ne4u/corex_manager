import json
import httpx
from typing import Any, Dict, List, Optional
from ..core.config import get_settings

settings = get_settings()


def _client() -> httpx.Client:
    # The Data Plane API uses a self-signed internal cert on the Docker network.
    # verify=False is safe here because traffic stays on the internal haproxy-net.
    # For production with a private CA, set DATAPLANE_API_CA_BUNDLE to verify.
    verify = getattr(settings, "DATAPLANE_API_CA_BUNDLE", None)
    return httpx.Client(
        base_url=settings.DATAPLANE_API_URL,
        auth=(settings.DATAPLANE_API_USER, settings.DATAPLANE_API_PASSWORD),
        timeout=30.0,
        verify=verify if verify else False,
    )


def _enabled() -> bool:
    return settings.DATAPLANE_API_ENABLED


def _convert_to_array(value: Any) -> Any:
    """Dataplane API requires lists for repeatable keywords.

    Simple helper to wrap scalar values that should be arrays.
    """
    return value


def get_info() -> Dict[str, Any]:
    """Get HAProxy process info from the Data Plane API."""
    if not _enabled():
        return {"enabled": False}
    try:
        with _client() as c:
            r = c.get("/services/haproxy/runtime/info")
            r.raise_for_status()
            return r.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_stats() -> List[Dict[str, Any]]:
    """Get HAProxy stats from the Data Plane API."""
    if not _enabled():
        return []
    try:
        with _client() as c:
            r = c.get("/services/haproxy/stats")
            r.raise_for_status()
            return r.json().get("data", [])
    except Exception:
        return []


def push_config(config_text: str) -> Dict[str, Any]:
    """Push a raw HAProxy configuration to the Data Plane API.

    Uses the raw configuration endpoint, which replaces the active config.
    """
    if not _enabled():
        return {"status": "ok", "message": "Data Plane API is disabled; config not pushed"}
    try:
        with _client() as c:
            # Fetch current config version first
            version_r = c.get("/services/haproxy/configuration/version")
            version = 1
            if version_r.status_code == 200:
                version = version_r.json().get("data", 1)
            r = c.post(
                f"/services/haproxy/configuration/raw?version={version}",
                data=config_text,
                headers={"Content-Type": "text/plain"},
            )
            r.raise_for_status()
            reload_id = r.headers.get("Reload-Id") or r.headers.get("Reload-ID")
            body = None
            if r.content:
                try:
                    body = r.json()
                except Exception:
                    body = r.text
            return {
                "status": "ok",
                "message": "Config pushed via Data Plane API",
                "reload_id": reload_id,
                "response": body,
            }
    except httpx.HTTPStatusError as e:
        detail = ""
        try:
            detail = e.response.text
        except Exception:
            pass
        return {"status": "error", "message": f"Data Plane API error: {detail or str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"Data Plane API error: {str(e)}"}


def reload_haproxy() -> Dict[str, Any]:
    """Trigger HAProxy reload through the Data Plane API."""
    if not _enabled():
        return {"status": "ok", "message": "Data Plane API is disabled"}
    try:
        with _client() as c:
            r = c.post("/services/haproxy/reloads?force_reload=true")
            r.raise_for_status()
            reload_id = r.headers.get("Reload-Id") or r.headers.get("Reload-ID")
            body = None
            if r.content:
                try:
                    body = r.json()
                except Exception:
                    body = r.text
            return {
                "status": "ok",
                "message": "HAProxy reloaded via Data Plane API",
                "reload_id": reload_id,
                "response": body,
            }
    except Exception as e:
        return {"status": "error", "message": f"Data Plane API reload failed: {str(e)}"}
