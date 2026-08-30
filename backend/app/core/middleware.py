import ipaddress
import json
import logging
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse
from .database import SessionLocal
from .security import decode_access_token
from ..models.models import AuditEvent, User
from ..services.audit import (
    derive_action,
    is_config_change,
    should_capture_payload,
    truncate_payload,
)
from ..core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _is_trusted_proxy(host: Optional[str]) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _get_forwarded_client(request: Request) -> Optional[str]:
    if not _is_trusted_proxy(request.client.host if request.client else None):
        return None
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        # The leftmost address is the original client (first trusted proxy in the chain).
        return x_forwarded_for.split(",")[0].strip()
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()
    return None


class ProxyHeadersMiddleware(BaseHTTPMiddleware):
    """Rewrite request.client from X-Forwarded-For/X-Real-IP when behind a trusted reverse proxy."""

    async def dispatch(self, request: Request, call_next):
        forwarded = _get_forwarded_client(request)
        if forwarded:
            port = request.scope["client"][1] if request.scope.get("client") else 0
            request.scope["client"] = (forwarded, port)
        return await call_next(request)


async def _buffer_response_body(response: StreamingResponse) -> bytes:
    """Consume a StreamingResponse body iterator and return the bytes."""
    chunks = []
    async for chunk in response.body_iterator:
        if isinstance(chunk, str):
            chunks.append(chunk.encode("utf-8"))
        else:
            chunks.append(chunk)
    return b"".join(chunks)


class AuditEventMiddleware(BaseHTTPMiddleware):
    """Logs config mutations, auth events, and config lifecycle actions to audit_events."""

    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path

        # Only audit mutating requests on API paths
        if method not in ("POST", "PUT", "DELETE", "PATCH"):
            return await call_next(request)
        if not path.startswith("/api/v1") or path == "/api/v1/health":
            return await call_next(request)

        # Read request body before handler runs (Starlette caches it)
        body_bytes = await request.body()
        content_type = request.headers.get("content-type")

        # Identify user from bearer token
        username = None
        user_id = None
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1]
            payload = decode_access_token(token)
            if payload:
                username = payload.get("sub")

        ip = request.client.host if request.client else None

        response = await call_next(request)

        # Derive semantic action and resource info
        action, resource_type, resource_id = derive_action(method, path)

        # For POST creates, try to extract resource_id from response body
        is_post = method == "POST"
        response_body_bytes: Optional[bytes] = None
        if is_post and resource_id is None and response.status_code < 400:
            try:
                response_body_bytes = await _buffer_response_body(response)
                try:
                    resp_json = json.loads(response_body_bytes.decode("utf-8"))
                    if isinstance(resp_json, dict) and "id" in resp_json:
                        resource_id = str(resp_json["id"])
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            except Exception:
                logger.debug("Could not buffer POST response body for audit", exc_info=True)

        # Build payload
        payload = None
        if should_capture_payload(path, content_type):
            payload = truncate_payload(body_bytes, settings.AUDIT_PAYLOAD_MAX_BYTES)

        # Resolve user_id if we have a username
        if username:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.username == username).first()
                if user:
                    user_id = user.id
            except Exception:
                pass
            finally:
                db.close()

        # Write the audit event
        db = SessionLocal()
        try:
            event = AuditEvent(
                user_id=user_id,
                username=username,
                action=action,
                method=method,
                path=path,
                resource_type=resource_type,
                resource_id=resource_id,
                status_code=response.status_code,
                ip_address=ip,
                payload=payload,
                config_change=is_config_change(method, path),
            )
            db.add(event)
            db.commit()
            db.refresh(event)
        except Exception:
            logger.exception("Failed to write audit event for %s %s", method, path)
            db.rollback()
        finally:
            db.close()

        # If we buffered the response body, re-wrap it
        if response_body_bytes is not None:
            return Response(
                content=response_body_bytes,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )
        return response
