import json
import httpx
from typing import Any, Dict, List, Optional, Tuple
from ..core.config import get_settings

settings = get_settings()


def _client(
    base_url: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> httpx.Client:
    """Build an httpx client for the Data Plane API.

    When ``base_url`` is provided (HA multi-instance mode), the caller's
    overrides take precedence; otherwise the global settings are used (the
    original single-instance behavior).
    """
    verify = getattr(settings, "DATAPLANE_API_CA_BUNDLE", None)
    return httpx.Client(
        base_url=base_url or settings.DATAPLANE_API_URL,
        auth=(
            user or settings.DATAPLANE_API_USER,
            password if password is not None else settings.DATAPLANE_API_PASSWORD,
        ),
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


def get_info(
    base_url: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Get HAProxy process info from the Data Plane API.

    When ``base_url`` is provided, queries that specific instance (HA mode);
    otherwise queries the default instance (single-instance mode).
    """
    if not _enabled():
        return {"enabled": False}
    try:
        with _client(base_url, user, password) as c:
            r = c.get("/services/haproxy/runtime/info")
            r.raise_for_status()
            return r.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_stats(
    base_url: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get HAProxy stats from the Data Plane API.

    When ``base_url`` is provided, queries that specific instance (HA mode).
    """
    if not _enabled():
        return []
    try:
        with _client(base_url, user, password) as c:
            r = c.get("/services/haproxy/stats")
            r.raise_for_status()
            return r.json().get("data", [])
    except Exception:
        return []


def push_config(
    config_text: str,
    base_url: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Push a raw HAProxy configuration to the Data Plane API.

    Uses the raw configuration endpoint, which replaces the active config.

    When ``base_url`` is provided (HA multi-instance mode), pushes to that
    specific instance; otherwise pushes to the default instance (the original
    single-instance behavior).
    """
    if not _enabled():
        return {"status": "ok", "message": "Data Plane API is disabled; config not pushed"}
    try:
        with _client(base_url, user, password) as c:
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


def reload_haproxy(
    base_url: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Trigger HAProxy reload through the Data Plane API.

    When ``base_url`` is provided, reloads that specific instance (HA mode).
    """
    if not _enabled():
        return {"status": "ok", "message": "Data Plane API is disabled"}
    try:
        with _client(base_url, user, password) as c:
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
