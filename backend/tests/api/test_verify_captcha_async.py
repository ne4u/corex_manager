"""Tests that the captcha verify path is non-blocking.

The ``verify_captcha`` endpoint is ``async def`` and must not issue blocking
network I/O. All captcha providers implement ``verify`` as an ``async def``
using ``httpx.AsyncClient``; this test pins that contract so a future provider
can't accidentally introduce a blocking ``requests`` call into the async path.
"""

import inspect

from app.services import captcha_providers


def _provider_classes():
    """Return all concrete captcha provider classes defined in the module."""
    classes = []
    for _name, obj in inspect.getmembers(captcha_providers, inspect.isclass):
        if obj.__module__ != captcha_providers.__name__:
            continue
        if obj.__name__ in ("BaseCaptchaProvider", "ABC"):
            continue
        if inspect.isabstract(obj):
            continue
        classes.append(obj)
    assert classes, "expected at least one concrete captcha provider"
    return classes


def test_all_providers_have_async_verify():
    for cls in _provider_classes():
        verify = getattr(cls, "verify", None)
        assert verify is not None, f"{cls.__name__} missing verify()"
        assert inspect.iscoroutinefunction(verify), (
            f"{cls.__name__}.verify must be async def (it runs inside the async "
            "verify_captcha endpoint and must not block the event loop)"
        )


def test_captcha_providers_module_uses_httpx_not_requests():
    """The providers module must use httpx (async) and must not import the
    blocking ``requests`` library."""
    src = inspect.getsource(captcha_providers)
    assert "httpx" in src
    assert "import requests" not in src, (
        "captcha_providers must not import requests — it runs in the async path"
    )
