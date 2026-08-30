"""ACME Certificate Authority metadata for acme.sh and certbot."""
from typing import Any, Dict, List, Optional

# CA short names supported by acme.sh, mapped to their directory URLs for certbot.
ACME_CA_MAP = {
    "zerossl": {
        "name": "ZeroSSL",
        "url": "https://acme.zerossl.com/v2/DV90",
        "help": "Requires EAB credentials for new accounts.",
    },
    "letsencrypt": {
        "name": "Let's Encrypt",
        "url": "https://acme-v02.api.letsencrypt.org/directory",
    },
    "letsencrypt_test": {
        "name": "Let's Encrypt Staging",
        "url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    },
    "buypass": {
        "name": "BuyPass",
        "url": "https://api.buypass.com/acme/directory",
    },
    "buypass_test": {
        "name": "BuyPass Test",
        "url": "https://api.test4.buypass.no/acme/directory",
    },
    "sslcom": {
        "name": "SSL.com",
        "url": "https://acme.ssl.com/sslcom-dv-rsa",
        "help": "RSA endpoint. Requires EAB credentials for new accounts.",
    },
    "sslcom_ecc": {
        "name": "SSL.com (ECC)",
        "url": "https://acme.ssl.com/sslcom-dv-ecc",
        "help": "ECC endpoint. Requires EAB credentials for new accounts.",
    },
    "google": {
        "name": "Google Public CA",
        "url": "https://dv.acme-v02.api.pki.goog/directory",
        "help": "Requires EAB credentials and Google Cloud project setup.",
    },
    "google_test": {
        "name": "Google Public CA (Test)",
        "url": "https://dv.acme-v02.test-api.pki.goog/directory",
    },
    "actalis": {
        "name": "Actalis",
        "url": "https://acme-api.actalis.com/acme/directory",
    },
    "pebble": {
        "name": "Pebble (test)",
        "url": "https://pebble:14000/dir",
        "help": "Local Let's Encrypt Pebble test CA.",
    },
}


def list_acme_cas() -> List[Dict[str, Any]]:
    """Return the supported CA list with short names and certbot URLs."""
    return [
        {"id": short, "name": meta["name"], "url": meta["url"], "help": meta.get("help")}
        for short, meta in ACME_CA_MAP.items()
    ]


def resolve_ca_server(ca_value: Optional[str], client: str) -> Optional[str]:
    """Return the --server value to pass to the ACME client.

    For acme.sh the short name is returned (or the raw URL).
    For certbot the directory URL is returned.
    """
    if not ca_value:
        return None
    if ca_value.startswith("http://") or ca_value.startswith("https://"):
        return ca_value
    if client == "acme.sh":
        return ca_value
    # certbot: map short names to directory URLs
    meta = ACME_CA_MAP.get(ca_value)
    if meta:
        return meta["url"]
    return ca_value
