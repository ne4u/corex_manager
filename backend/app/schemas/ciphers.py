from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class CipherSuiteBase(BaseModel):
    name: str
    baseline: str = Field(..., pattern="^(fips|fedramp|pci|modern|custom)$")
    ciphers: Optional[str] = None
    tls_options: Optional[str] = "no-sslv3 no-tlsv10 no-tlsv11"
    min_tls_version: Optional[str] = "TLSv1.2"
    quantum_safe: bool = False
    hsts_enabled: bool = True
    hsts_max_age: Optional[int] = 31536000
    hsts_include_subdomains: Optional[bool] = True
    hsts_preload: Optional[bool] = False


class CipherSuiteCreate(CipherSuiteBase):
    pass


CipherSuiteUpdate = _optional_update(CipherSuiteBase)


class CipherSuiteResponse(CipherSuiteBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


__all__ = ['CipherSuiteBase', 'CipherSuiteCreate', 'CipherSuiteResponse', 'CipherSuiteUpdate']
