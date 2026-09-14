from pydantic import BaseModel, ConfigDict, Field

from ._base import _optional_update


class CipherSuiteBase(BaseModel):
    name: str
    baseline: str = Field(..., pattern="^(fips|fedramp|pci|modern|custom)$")
    ciphers: str | None = None
    tls_options: str | None = "no-sslv3 no-tlsv10 no-tlsv11"
    min_tls_version: str | None = "TLSv1.2"
    quantum_safe: bool = False
    hsts_enabled: bool = True
    hsts_max_age: int | None = 31536000
    hsts_include_subdomains: bool | None = True
    hsts_preload: bool | None = False


class CipherSuiteCreate(CipherSuiteBase):
    pass


CipherSuiteUpdate = _optional_update(CipherSuiteBase)


class CipherSuiteResponse(CipherSuiteBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


__all__ = ["CipherSuiteBase", "CipherSuiteCreate", "CipherSuiteResponse", "CipherSuiteUpdate"]
