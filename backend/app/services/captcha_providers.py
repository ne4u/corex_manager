"""CAPTCHA provider abstraction for multi-provider support.

Supports three providers:
  - Cap (labeled "Native" in the UI — the built-in proof-of-work CAPTCHA)
  - Google reCAPTCHA v2/v3
  - Cloudflare Turnstile

Each provider contributes: widget HTML, script tags, CSP directives, token
field name, verify logic, and whether it needs the HAProxy service proxy.
The surrounding challenge page template is shared via render_challenge_page().
"""
from __future__ import annotations

import hashlib
import html as _html
import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Client-binding hash for the _cv captcha validation cookie
# ---------------------------------------------------------------------------

def compute_cv_binding_hash(ip: str, user_agent: str, ja4: str) -> str:
    """Compute the client-binding hash for a solved captcha cookie.

    Binds the _cv token to the client that solved the challenge so a leaked
    cookie cannot be replayed from a different client. The hash covers:
      - client IP (as seen by HAProxy, forwarded via X-Forwarded-For)
      - User-Agent header
      - JA4 TLS fingerprint (forwarded via X-JA4-Fingerprint, empty for
        plaintext listeners or when JA4 is disabled)

    The same algorithm is implemented in haproxy/lua/captcha_ctx.lua
    (captcha_validate_cookie) and MUST stay in sync. The format is:

        sha256(f"{ip}\\n{user_agent}\\n{ja4}")  → first 32 hex chars (128 bits)

    Components that are missing/empty (e.g. no UA, plaintext JA4) are
    represented as empty strings on both sides, so the hash still matches.
    """
    payload = f"{ip}\n{user_agent}\n{ja4}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class CaptchaProvider:
    """Base CAPTCHA provider interface."""

    name: str = ""
    display_name: str = ""

    def render_widget_html(self, site_key: str, proxy_path: str) -> str:
        """Return the widget HTML element (not the full page)."""
        raise NotImplementedError

    def render_script_html(self, cfg: Any) -> str:
        """Return <script> tags for the widget."""
        raise NotImplementedError

    def get_csp_directives(self) -> str:
        """Return CSP directives for the challenge page."""
        raise NotImplementedError

    def get_token_field_name(self) -> str:
        """Return the form field name that carries the captcha token."""
        raise NotImplementedError

    def is_invisible(self) -> bool:
        """True if the widget auto-submits (no Continue button needed)."""
        return False

    def needs_service_proxy(self) -> bool:
        """True if the widget makes API calls that need HAProxy proxying."""
        return False

    async def verify(self, token: str, secret: str, remote_ip: Optional[str] = None) -> bool:
        """Verify a captcha token. Returns True on success."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Cap (Native) provider
# ---------------------------------------------------------------------------

class CapProvider(CaptchaProvider):
    name = "cap"
    display_name = "Native"

    def render_widget_html(self, site_key: str, proxy_path: str) -> str:
        api_endpoint = f"{proxy_path}/{site_key}/"
        # The hidden input is placed OUTSIDE the <cap-widget> because the
        # widget clears its own light DOM children (this.#o.innerHTML = '')
        # during connectedCallback. The solve-event listener in
        # render_script_html populates this input when the widget solves.
        return (
            f'<cap-widget data-cap-api-endpoint="{_html.escape(api_endpoint)}" '
            f'data-cap-hidden-field-name="cap_token"></cap-widget>'
            f'<input type="hidden" name="cap_token" />'
        )

    def render_script_html(self, cfg: Any) -> str:
        widget_cdn = cfg.CAPTCHA_WIDGET_CDN_URL
        return (
            '<script>window.CAP_CUSTOM_WASM_URL = '
            '"https://cdn.jsdelivr.net/npm/@cap.js/wasm@0.0.7/browser/cap_wasm_bg.wasm";</script>\n'
            f'  <script src="{_html.escape(widget_cdn)}" async defer></script>\n'
            '  <script>\n'
            '  // The Cap widget clears its light DOM children on init, so the\n'
            '  // hidden cap_token input lives outside the widget. Listen for\n'
            '  // the widget\'s "solve" event to populate it.\n'
            '  (function() {\n'
            '    var form = document.getElementById("captcha-form");\n'
            '    if (!form) return;\n'
            '    var widget = form.querySelector("cap-widget");\n'
            '    var tokenInput = form.querySelector(\'input[name="cap_token"]\');\n'
            '    if (!widget || !tokenInput) return;\n'
            '    widget.addEventListener("solve", function(e) {\n'
            '      if (e.detail && e.detail.token) {\n'
            '        tokenInput.value = e.detail.token;\n'
            '      }\n'
            '    });\n'
            '    widget.addEventListener("reset", function() {\n'
            '      tokenInput.value = "";\n'
            '    });\n'
            '  })();\n'
            '  </script>'
        )

    def get_csp_directives(self) -> str:
        # Cap renders its widget inside an iframe with srcdoc, which inherits
        # this page's CSP. The widget's bundled JS uses eval/new Function for
        # its proof-of-work solver and embeds small images as data: URIs, so
        # script-src needs 'unsafe-eval' and img-src needs data:.
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net 'wasm-unsafe-eval'; "
            "worker-src blob:; "
            "connect-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-src 'self'"
        )

    def get_token_field_name(self) -> str:
        return "cap_token"

    def needs_service_proxy(self) -> bool:
        return True

    async def verify(self, token: str, secret: str, remote_ip: Optional[str] = None) -> bool:
        if not token or not secret:
            return False
        cfg = _get_settings()
        service_url = getattr(cfg, "CAPTCHA_SERVICE_URL", "http://cap:3000")
        # Read site key from the settings table first (consistent with how the
        # challenge page reads it via _get_provider_site_key), then fall back to
        # the env var. A mismatch here causes the Cap service to reject tokens
        # because the siteverify URL contains the wrong site key.
        site_key = ""
        try:
            from ..services.settings import get_setting as _gs
            from ..core.database import SessionLocal
            _db = SessionLocal()
            try:
                site_key = _gs(_db, "cap_site_key") or ""
            finally:
                _db.close()
        except Exception:
            pass
        if not site_key:
            site_key = getattr(cfg, "CAPTCHA_SITE_KEY", None) or ""
        # Cap API expects POST /{siteKey}/siteverify with JSON body
        url = f"{service_url.rstrip('/')}/{site_key}/siteverify" if site_key else f"{service_url.rstrip('/')}/siteverify"
        try:
            async with httpx.AsyncClient() as client:
                res = await client.post(
                    url,
                    json={"secret": secret, "response": token},
                    timeout=10,
                )
        except Exception as exc:
            logger.warning("Cap verify: request to %s failed: %s", url, exc)
            raise
        if res.status_code != 200:
            logger.warning(
                "Cap verify: %s returned status %s, body: %s",
                url, res.status_code, res.text[:500],
            )
            return False
        try:
            data = res.json()
        except Exception:
            logger.warning("Cap verify: %s returned non-JSON response: %s", url, res.text[:500])
            return False
        success = bool(data.get("success"))
        if not success:
            logger.info(
                "Cap verify: token rejected by %s. success=%s, error=%s",
                url, data.get("success"), data.get("error"),
            )
        return success


# ---------------------------------------------------------------------------
# reCAPTCHA provider
# ---------------------------------------------------------------------------

class RecaptchaProvider(CaptchaProvider):
    name = "recaptcha"
    display_name = "reCAPTCHA"

    def __init__(self, version: str = "v2", min_score: float = 0.5):
        self._version = version
        self._min_score = min_score

    def render_widget_html(self, site_key: str, proxy_path: str) -> str:
        if self._version == "v3":
            # v3 is invisible — the token is obtained via JS callback
            return f'<div id="recaptcha-container" data-sitekey="{_html.escape(site_key)}"></div>'
        # v2 — checkbox/image challenge
        return (
            f'<div class="g-recaptcha" data-sitekey="{_html.escape(site_key)}" '
            f'style="display:inline-block;"></div>'
        )

    def render_script_html(self, cfg: Any) -> str:
        return (
            '<script src="https://www.google.com/recaptcha/api.js" async defer></script>'
        )

    def get_csp_directives(self) -> str:
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
            "frame-src https://www.google.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https://www.gstatic.com https://www.google.com; "
            "connect-src 'self' https://www.google.com https://www.gstatic.com"
        )

    def get_token_field_name(self) -> str:
        return "g-recaptcha-response"

    def is_invisible(self) -> bool:
        return self._version == "v3"

    async def verify(self, token: str, secret: str, remote_ip: Optional[str] = None) -> bool:
        if not token or not secret:
            return False
        async with httpx.AsyncClient() as client:
            data: Dict[str, Any] = {"secret": secret, "response": token}
            if remote_ip:
                data["remoteip"] = remote_ip
            res = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data=data,
                timeout=10,
            )
        result = res.json()
        if not result.get("success"):
            return False
        # v3: check score threshold
        if self._version == "v3":
            score = result.get("score", 0.0)
            if score < self._min_score:
                return False
        return True


# ---------------------------------------------------------------------------
# Turnstile provider
# ---------------------------------------------------------------------------

class TurnstileProvider(CaptchaProvider):
    name = "turnstile"
    display_name = "Turnstile"

    def render_widget_html(self, site_key: str, proxy_path: str) -> str:
        return (
            f'<div class="cf-turnstile" data-sitekey="{_html.escape(site_key)}" '
            f'style="display:inline-block;"></div>'
        )

    def render_script_html(self, cfg: Any) -> str:
        return (
            '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        )

    def get_csp_directives(self) -> str:
        return (
            "default-src 'self'; "
            "script-src 'self' https://challenges.cloudflare.com 'unsafe-inline'; "
            "frame-src https://challenges.cloudflare.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' https://challenges.cloudflare.com"
        )

    def get_token_field_name(self) -> str:
        return "cf-turnstile-response"

    async def verify(self, token: str, secret: str, remote_ip: Optional[str] = None) -> bool:
        if not token or not secret:
            return False
        async with httpx.AsyncClient() as client:
            data: Dict[str, Any] = {"secret": secret, "response": token}
            if remote_ip:
                data["remoteip"] = remote_ip
            res = await client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data=data,
                timeout=10,
            )
        result = res.json()
        return bool(result.get("success"))


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS = {
    "cap": CapProvider,
    "recaptcha": RecaptchaProvider,
    "turnstile": TurnstileProvider,
}


def get_provider(name: str, **kwargs: Any) -> CaptchaProvider:
    """Return a provider instance by name.

    For reCAPTCHA, version and min_score can be passed as kwargs or read
    from the settings table by the caller.
    """
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(f"Unknown captcha provider: {name!r}")
    return cls(**kwargs) if cls is RecaptchaProvider else cls()


def get_provider_display_name(name: str) -> str:
    """Return the UI display name for a provider."""
    cls = _PROVIDERS.get(name)
    if cls is None:
        return name
    return cls.display_name


# ---------------------------------------------------------------------------
# Shared challenge page template
# ---------------------------------------------------------------------------

def render_challenge_page(
    widget_html: str,
    script_html: str,
    csp: str,
    form_action: str,
    hidden_fields: Dict[str, str],
    request_id: str,
    is_invisible: bool,
) -> str:
    """Render the shared dark-themed challenge page.

    All providers share this template — only the widget HTML and script tags
    differ. The page includes a loading spinner, request ID footer, and either
    a Continue button (visible providers) or auto-submit JS (invisible providers).
    """
    hidden_inputs = "\n".join(
        f'    <input type="hidden" name="{_html.escape(k)}" value="{_html.escape(v)}" />'
        for k, v in hidden_fields.items()
    )
    button_html = "" if is_invisible else (
        '<br/>\n    <button type="submit" class="btn">Continue</button>'
    )
    auto_submit_js = ""
    if is_invisible:
        # Auto-submit when a token appears in the form (reCAPTCHA v3 / Turnstile invisible)
        auto_submit_js = """  <script>
  (function() {
    var form = document.getElementById('captcha-form');
    var checkAndSubmit = function() {
      var inputs = form.querySelectorAll('input[type=hidden]');
      for (var i = 0; i < inputs.length; i++) {
        if (inputs[i].name.indexOf('-response') !== -1 || inputs[i].name === 'cap_token') {
          if (inputs[i].value && inputs[i].value.length > 0) {
            form.submit();
            return;
          }
        }
      }
      setTimeout(checkAndSubmit, 200);
    };
    // Give the widget script time to load and execute
    setTimeout(checkAndSubmit, 1000);
  })();
  </script>"""
    rid_display = _html.escape(request_id) if request_id else "—"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Check</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="{csp}">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 2.5rem 2rem;
      max-width: 420px;
      width: 100%;
      text-align: center;
      box-shadow: 0 10px 40px rgba(0,0,0,0.4);
    }}
    .icon {{
      width: 48px; height: 48px;
      margin: 0 auto 1rem;
      color: #3b82f6;
    }}
    h2 {{ font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem; }}
    .subtitle {{ color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem; }}
    .widget-container {{ margin: 1.5rem 0; display: flex; justify-content: center; min-height: 65px; position: relative; }}
    .btn {{
      background: #3b82f6; color: #fff; border: none; border-radius: 8px;
      padding: 0.6rem 1.5rem; font-size: 0.95rem; cursor: pointer;
      transition: background 0.15s;
    }}
    .btn:hover {{ background: #2563eb; }}
    .footer {{
      margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #334155;
      font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem;
      color: #64748b; cursor: pointer; user-select: all;
    }}
    .footer:hover {{ color: #94a3b8; }}
    .spinner {{
      width: 32px; height: 32px; border: 3px solid #334155;
      border-top-color: #3b82f6; border-radius: 50%;
      animation: spin 0.8s linear infinite;
      position: absolute; top: 50%; left: 50%;
      transform: translate(-50%, -50%);
    }}
    @keyframes spin {{
      from {{ transform: translate(-50%, -50%) rotate(0deg); }}
      to {{ transform: translate(-50%, -50%) rotate(360deg); }}
    }}
  </style>
</head>
<body>
  <div class="card">
    <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    <h2>Security Check</h2>
    <p class="subtitle">Please complete the verification below to continue.</p>
    <form id="captcha-form" method="post" action="{_html.escape(form_action)}">
{hidden_inputs}
      <div class="widget-container">
        <div class="spinner" id="loading-spinner"></div>
        <div id="widget-wrapper">{widget_html}</div>
      </div>{button_html}
    </form>
    <div class="footer" onclick="navigator.clipboard&&navigator.clipboard.writeText(this.textContent)">Request ID: {rid_display}</div>
  </div>
  <script>
  // Hide spinner once the widget renders (MutationObserver on widget-wrapper children)
  (function() {{
    var wrapper = document.getElementById('widget-wrapper');
    var spinner = document.getElementById('loading-spinner');
    if (wrapper && spinner) {{
      var hideSpinner = function() {{
        if (wrapper.children.length > 0 || wrapper.innerHTML.trim()) {{
          spinner.style.display = 'none';
        }}
      }};
      var obs = new MutationObserver(hideSpinner);
      obs.observe(wrapper, {{childList: true, subtree: true, attributes: true}});
      // Fallback: hide spinner after 2s even if MutationObserver doesn't fire
      setTimeout(function() {{ spinner.style.display = 'none'; }}, 2000);
    }}
  }})();
  </script>
  {script_html}
{auto_submit_js}
</body>
</html>"""


def render_error_page(title: str, message: str, request_id: str, status: int = 400) -> str:
    """Render a shared dark-themed error page with the request ID."""
    rid_display = _html.escape(request_id) if request_id else "—"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{_html.escape(title)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f172a; color: #e2e8f0;
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 1rem;
    }}
    .card {{
      background: #1e293b; border: 1px solid #334155; border-radius: 12px;
      padding: 2.5rem 2rem; max-width: 420px; width: 100%; text-align: center;
      box-shadow: 0 10px 40px rgba(0,0,0,0.4);
    }}
    h2 {{ font-size: 1.25rem; font-weight: 600; margin-bottom: 0.75rem; color: #ef4444; }}
    p {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 1rem; }}
    a {{ color: #3b82f6; text-decoration: none; font-size: 0.9rem; }}
    a:hover {{ text-decoration: underline; }}
    .footer {{
      margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #334155;
      font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem;
      color: #64748b; user-select: all;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h2>{_html.escape(title)}</h2>
    <p>{_html.escape(message)}</p>
    <a href="/">Continue</a>
    <div class="footer">Request ID: {rid_display}</div>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_settings():
    """Lazy import to avoid circular imports."""
    from ..core.config import get_settings
    return get_settings()
