"""Page Protect hasher — fetches detected scripts and detects code changes.

Background thread that periodically fetches each detected script URL, computes
a SHA-256 hash of its content, and compares it to the last-known hash. When a
change is detected, the script's hash_changed flag is set. The decoded body is
persisted so an AI agent or user can later inspect the actual content.
"""
import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.models import PageProtectScript
from .page_protect import get_page_protect_settings

logger = logging.getLogger(__name__)

settings = get_settings()


@dataclass
class FetchResult:
    """Result of a successful asset fetch."""
    hash: str
    content: Optional[str]
    content_type: Optional[str]


# Content types we are willing to store as text for AI/manual analysis.
_TEXT_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "text/javascript",
    "text/css",
    "text/xml",
    "application/javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/x-javascript",
    "application/ecmascript",
    "application/manifest+json",
    "application/ld+json",
}


def _decode_text_content(resp) -> Optional[str]:
    """Decode response bytes to text if the content type looks text-ish.

    Returns None for obvious binary payloads (images, fonts, etc.) or if the
    decoded text is empty. Unknown/missing content types are treated as text.
    """
    content_type = resp.headers.get("content-type")
    if content_type:
        ct = content_type.split(";")[0].strip().lower()
        if ct and ct not in _TEXT_CONTENT_TYPES:
            # Known binary or non-text content type -- don't store as text.
            return None
    try:
        text = resp.content.decode("utf-8", errors="replace")
    except Exception:
        return None
    if not text:
        return None
    return text


def _hasher_headers() -> dict:
    """Build browser-like request headers for the hasher.

    The User-Agent stays as the non-browser coreX-Manager-PageProtect/2.0
    string (so HAProxy can identify hasher requests), but every other header
    mimics a modern browser to avoid being flagged by origin-side bot
    detection. A secret internal bypass header is included so HAProxy can
    skip logging, risk scoring, security rules, rate limiting, and WAF for
    the hasher's local requests.
    """
    return {
        "User-Agent": settings.PAGE_PROTECT_HASH_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Sec-Ch-Ua": '"Chromium";v="124", "Not:A-Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Upgrade-Insecure-Requests": "1",
        settings.PAGE_PROTECT_HASHER_BYPASS_HEADER: settings.PAGE_PROTECT_HASHER_BYPASS_TOKEN,
    }


def hash_script(script: PageProtectScript) -> Optional[FetchResult]:
    """Fetch a script URL and return its hash, decoded text, and content type.

    Returns None on error or if the URL is not HTTP(S). The decoded text is
    only included for text-like content types so the database is not filled
    with binary payloads.

    The HTTP method is determined by ``script.fetch_method``:
    - ``"GET"`` / ``"POST"``: always use that method.
    - ``"auto"`` (default): use ``last_fetch_method`` if set; otherwise probe
      GET, and on 405/403 fall back to POST. The working method is persisted
      to ``last_fetch_method`` so the probe cost is one-time.
    """
    url = script.url
    if not url or not url.startswith(("http://", "https://")):
        return None
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed; cannot hash scripts")
        return None

    configured = (script.fetch_method or "auto").upper()
    if configured == "AUTO":
        method = (script.last_fetch_method or "GET").upper()
    else:
        method = configured

    try:
        with httpx.Client(
            timeout=settings.PAGE_PROTECT_HASH_TIMEOUT_SECONDS,
            headers=_hasher_headers(),
            follow_redirects=True,
        ) as client:
            resp = client.request(method, url)
            # Auto-probe: if GET is rejected (405 Method Not Allowed or 403
            # Forbidden), retry with POST. Only probe when configured as
            # "auto" and we haven't already persisted a working method.
            if (
                configured == "AUTO"
                and not script.last_fetch_method
                and resp.status_code in (403, 405)
                and method != "POST"
            ):
                logger.info("GET rejected (%d) for %s, retrying with POST", resp.status_code, url)
                method = "POST"
                resp = client.request(method, url)
            resp.raise_for_status()
            # Persist the working method for auto-mode scripts.
            if configured == "AUTO" and script.last_fetch_method != method:
                script.last_fetch_method = method
            content_hash = hashlib.sha256(resp.content).hexdigest()
            content_type = resp.headers.get("content-type")
            text = _decode_text_content(resp)
            return FetchResult(hash=content_hash, content=text, content_type=content_type)
    except Exception as exc:
        logger.warning("Failed to hash script %s: %s", url, exc)
        return None


def check_script(db: Session, script: PageProtectScript) -> Optional[str]:
    """Hash a single script and update its hash fields. Returns the new hash or None.

    On a successful fetch the decoded body is also persisted (when the hash
    changes, on the first successful check, or if no content has been stored
    yet) so an AI agent or user can later inspect the actual payload.

    On fetch failure, ``hash_checked_at`` is still updated (but ``last_hash_at``
    is not) so the UI can distinguish "checked but failed" (``hash_checked_at``
    more recent than ``last_hash_at``) from "never checked" (both None) and
    from "checked successfully" (``last_hash_at`` == ``hash_checked_at``).

    Ignored assets are skipped entirely so dynamic or authenticated resources
    are not repeatedly probed.
    """
    if script.ignored:
        return None
    result = hash_script(script)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if result is None:
        # Record that a check was attempted even on failure
        script.hash_checked_at = now
        db.flush()
        return None
    new_hash = result.hash
    text = result.content
    if script.first_hash is None:
        script.first_hash = new_hash
        script.first_hash_at = now
        script.last_hash = new_hash
        script.last_hash_at = now
        script.hash_checked_at = now
        script.hash_changed = False
        if text is not None:
            script.content = text
    elif script.last_hash != new_hash:
        script.last_hash = new_hash
        script.last_hash_at = now
        script.hash_checked_at = now
        script.hash_changed = True
        if text is not None:
            script.content = text
        logger.info("Code change detected for script %s", script.url)
    else:
        script.last_hash_at = now
        script.hash_checked_at = now
        if script.content is None and text is not None:
            script.content = text
    db.flush()
    return new_hash


def reset_script_hash(db: Session, script: PageProtectScript) -> None:
    """Clear a script's hash fields so the next check establishes a fresh baseline.

    Useful when a known event (planned deployment, CDN cache purge) changes an
    asset's content — the user resets the hash so the change isn't flagged as a
    supply-chain alert. The next ``check_script`` call will set ``first_hash``
    and ``last_hash`` to the current content hash with ``hash_changed=False``.
    """
    script.first_hash = None
    script.first_hash_at = None
    script.last_hash = None
    script.last_hash_at = None
    script.hash_checked_at = None
    script.hash_changed = False
    db.flush()


def check_all_scripts(db: Session, force: bool = False) -> int:
    """Check all scripts that are due for hashing. Returns the number checked.

    Scripts are checked indefinitely once added to the inventory — there is no
    auto-pruning. The only way a script leaves the inventory is manual deletion.
    ``force=True`` overrides the per-script interval check — used by the manual
    "check all" button.
    """
    pp_settings = get_page_protect_settings(db)
    interval_hours = pp_settings.get("change_detection_interval_hours", 24)
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=interval_hours)

    scripts = db.query(PageProtectScript).filter(PageProtectScript.ignored == False).all()  # noqa: E712
    checked = 0
    attempted = 0
    for script in scripts:
        if not force:
            # Skip if checked recently
            if script.hash_checked_at and script.hash_checked_at > cutoff:
                continue
        attempted += 1
        result = check_script(db, script)
        if result is not None:
            checked += 1
    if attempted:
        db.commit()
    return checked


def _hasher_loop() -> None:
    """Background loop: check for due scripts every 60 seconds."""
    while True:
        try:
            time.sleep(60)
            db = SessionLocal()
            try:
                pp_settings = get_page_protect_settings(db)
                if not pp_settings.get("change_detection_enabled", False):
                    continue
                check_all_scripts(db)
            finally:
                db.close()
        except Exception as exc:
            logger.exception("Page Protect hasher loop error: %s", exc)


def start_page_protect_hasher() -> None:
    thread = threading.Thread(target=_hasher_loop, daemon=True)
    thread.start()
