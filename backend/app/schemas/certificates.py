from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CertificateBase(BaseModel):
    name: str
    domain: str | None = None
    kind: str = Field(default="server", pattern="^(server|client|ca)$")
    provider: str = "letsencrypt"
    email: str | None = None
    is_wildcard: bool = False
    auto_renew: bool = True
    key_type: str = "ecdsa-p384"
    acme_challenge: str = "dns"
    acme_ca: str | None = None
    dns_provider: str | None = None


class CertificateCreate(CertificateBase):
    dns_credentials: dict[str, Any] | None = None
    fullchain: str | None = None
    key: str | None = None
    chain: str | None = None

    @model_validator(mode="after")
    def _require_domain_for_letsencrypt(self):
        if self.provider == "letsencrypt" and not self.domain:
            raise ValueError("Domain is required for Let's Encrypt certificates")
        return self


class CertificateUpdate(BaseModel):
    name: str | None = None
    domain: str | None = None
    kind: str | None = Field(default=None, pattern="^(server|client|ca)$")
    provider: str | None = None
    email: str | None = None
    is_wildcard: bool | None = None
    auto_renew: bool | None = None
    key_type: str | None = None
    acme_challenge: str | None = None
    acme_ca: str | None = None
    dns_provider: str | None = None
    dns_credentials: dict[str, Any] | None = None
    fullchain: str | None = None
    key: str | None = None
    chain: str | None = None


class CertificateResponse(CertificateBase):
    id: int
    cert_path: str | None
    key_path: str | None
    chain_path: str | None
    not_before: datetime | None
    not_after: datetime | None
    subject_cn: str | None = None
    sans: str | None = None
    dns_credentials_set: bool = False
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _compute_credentials_set(cls, values: Any) -> Any:
        creds = None
        if isinstance(values, dict):
            creds = values.get("dns_credentials")
            values["dns_credentials_set"] = bool(creds)
        else:
            creds = getattr(values, "dns_credentials", None)
            setattr(values, "dns_credentials_set", bool(creds))
        return values

    model_config = ConfigDict(from_attributes=True)


class DnsProviderField(BaseModel):
    name: str
    label: str
    type: str = "text"
    required: bool = False
    help: str | None = None
    options: list[str] | None = None


class DnsProviderClient(BaseModel):
    code: str | None = None
    plugin: str | None = None
    env: list[DnsProviderField] | None = None
    credentials_keys: list[DnsProviderField] | None = None
    custom_code: bool | None = False
    custom_env: bool | None = False
    custom_plugin: bool | None = False
    custom_credentials: bool | None = False


class DnsProvider(BaseModel):
    id: str
    name: str
    acme_sh: DnsProviderClient | None = None
    certbot: DnsProviderClient | None = None


class DnsProviderResponse(BaseModel):
    client: str
    providers: list[DnsProvider]


class AcmeCa(BaseModel):
    id: str
    name: str
    url: str
    help: str | None = None


class AcmeCaResponse(BaseModel):
    cas: list[AcmeCa]


__all__ = [
    "AcmeCa",
    "AcmeCaResponse",
    "CertificateBase",
    "CertificateCreate",
    "CertificateResponse",
    "CertificateUpdate",
    "DnsProvider",
    "DnsProviderClient",
    "DnsProviderField",
    "DnsProviderResponse",
]
