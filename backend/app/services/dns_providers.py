import json
import os
from typing import Any, Dict, List, Optional

from ..core.config import get_settings

settings = get_settings()

_dns_providers: Optional[Dict[str, Any]] = None


def _load_dns_providers() -> Dict[str, Any]:
    global _dns_providers
    if _dns_providers is not None:
        return _dns_providers
    path = os.path.join(os.path.dirname(__file__), "dns_providers.json")
    with open(path, "r", encoding="utf-8") as f:
        _dns_providers = json.load(f)
    return _dns_providers


def get_active_acme_client() -> str:
    """Return 'acme.sh' or 'certbot' based on the current settings."""
    return "acme.sh" if settings.ACME_SH_ENABLED else "certbot"


def _client_key(client: str) -> str:
    """Map the client string to the JSON key used in dns_providers.json.

    The JSON file stores acme.sh metadata under the key ``acme_sh`` (underscore),
    but the rest of the codebase refers to the client as ``acme.sh`` (with a dot).
    This normalizes the lookup so callers can use either form.
    """
    return "acme_sh" if client == "acme.sh" else client


def list_dns_providers() -> List[Dict[str, Any]]:
    """Return the configured DNS provider metadata list."""
    data = _load_dns_providers()
    return data.get("providers", [])


def get_dns_provider(provider_id: str) -> Optional[Dict[str, Any]]:
    for provider in list_dns_providers():
        if provider.get("id") == provider_id:
            return provider
    return None


def get_provider_code(provider_id: str, client: Optional[str] = None) -> Optional[str]:
    client = client or get_active_acme_client()
    provider = get_dns_provider(provider_id)
    if not provider:
        return None
    client_meta = provider.get(_client_key(client), {})
    return client_meta.get("code") or client_meta.get("plugin")


def get_provider_credentials_config(provider_id: str, client: Optional[str] = None) -> Optional[Dict[str, Any]]:
    client = client or get_active_acme_client()
    provider = get_dns_provider(provider_id)
    if not provider:
        return None
    return provider.get(_client_key(client))


def get_provider_credential_keys(provider_id: str, client: Optional[str] = None) -> List[Dict[str, Any]]:
    client = client or get_active_acme_client()
    config = get_provider_credentials_config(provider_id, client)
    if not config:
        return []
    if client == "acme.sh":
        return config.get("env", [])
    return config.get("credentials_keys", [])


def validate_dns_credentials(provider_id: str, credentials: Dict[str, Any], client: Optional[str] = None) -> Optional[str]:
    client = client or get_active_acme_client()
    config = get_provider_credentials_config(provider_id, client)
    if not config:
        return f"DNS provider {provider_id} not supported by {client}"

    # Custom provider: user supplies their own keys and the provider/plugin code
    if config.get("custom_code") or config.get("custom_plugin"):
        if not credentials:
            return "DNS credentials are required"
        real_keys = [k for k in credentials if not k.startswith("_")]
        if not real_keys:
            return "At least one DNS credential key is required"
        return None

    if client == "acme.sh":
        required = [f["name"] for f in config.get("env", []) if f.get("required")]
    else:
        required = [f["name"] for f in config.get("credentials_keys", []) if f.get("required")]

    missing = [k for k in required if not credentials or not credentials.get(k)]
    if missing:
        return f"Missing DNS credentials: {', '.join(missing)}"
    return None
