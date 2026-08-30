from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class CertificateBase(BaseModel):
    name: str
    domain: Optional[str] = None
    kind: str = Field(default="server", pattern="^(server|client|ca)$")
    provider: str = "letsencrypt"
    email: Optional[str] = None
    is_wildcard: bool = False
    auto_renew: bool = True
    key_type: str = "ecdsa-p384"
    acme_challenge: str = "dns"
    acme_ca: Optional[str] = None
    dns_provider: Optional[str] = None


class CertificateCreate(CertificateBase):
    dns_credentials: Optional[Dict[str, Any]] = None
    fullchain: Optional[str] = None
    key: Optional[str] = None
    chain: Optional[str] = None

    @model_validator(mode='after')
    def _require_domain_for_letsencrypt(self):
        if self.provider == 'letsencrypt' and not self.domain:
            raise ValueError('Domain is required for Let\'s Encrypt certificates')
        return self


class CertificateUpdate(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    kind: Optional[str] = Field(default=None, pattern="^(server|client|ca)$")
    provider: Optional[str] = None
    email: Optional[str] = None
    is_wildcard: Optional[bool] = None
    auto_renew: Optional[bool] = None
    key_type: Optional[str] = None
    acme_challenge: Optional[str] = None
    acme_ca: Optional[str] = None
    dns_provider: Optional[str] = None
    dns_credentials: Optional[Dict[str, Any]] = None
    fullchain: Optional[str] = None
    key: Optional[str] = None
    chain: Optional[str] = None


class CertificateResponse(CertificateBase):
    id: int
    cert_path: Optional[str]
    key_path: Optional[str]
    chain_path: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    subject_cn: Optional[str] = None
    sans: Optional[str] = None
    dns_credentials_set: bool = False
    created_at: datetime
    updated_at: datetime

    @model_validator(mode='before')
    @classmethod
    def _compute_credentials_set(cls, values: Any) -> Any:
        creds = None
        if isinstance(values, dict):
            creds = values.get('dns_credentials')
            values['dns_credentials_set'] = bool(creds)
        else:
            creds = getattr(values, 'dns_credentials', None)
            setattr(values, 'dns_credentials_set', bool(creds))
        return values

    model_config = ConfigDict(from_attributes=True)


class DnsProviderField(BaseModel):
    name: str
    label: str
    type: str = "text"
    required: bool = False
    help: Optional[str] = None
    options: Optional[List[str]] = None


class DnsProviderClient(BaseModel):
    code: Optional[str] = None
    plugin: Optional[str] = None
    env: Optional[List[DnsProviderField]] = None
    credentials_keys: Optional[List[DnsProviderField]] = None
    custom_code: Optional[bool] = False
    custom_env: Optional[bool] = False
    custom_plugin: Optional[bool] = False
    custom_credentials: Optional[bool] = False


class DnsProvider(BaseModel):
    id: str
    name: str
    acme_sh: Optional[DnsProviderClient] = None
    certbot: Optional[DnsProviderClient] = None


class DnsProviderResponse(BaseModel):
    client: str
    providers: List[DnsProvider]


class AcmeCa(BaseModel):
    id: str
    name: str
    url: str
    help: Optional[str] = None


class AcmeCaResponse(BaseModel):
    cas: List[AcmeCa]


__all__ = ['AcmeCa', 'AcmeCaResponse', 'CertificateBase', 'CertificateCreate', 'CertificateResponse', 'CertificateUpdate', 'DnsProvider', 'DnsProviderClient', 'DnsProviderField', 'DnsProviderResponse']
