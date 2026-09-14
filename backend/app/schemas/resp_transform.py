import re as _re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ._base import _optional_update

_VALID_TRANSFORM_TYPES = {"replace", "inject", "mask"}
_VALID_INJECT_POSITIONS = {"before", "after", "replace"}
_VALID_MASK_MODES = {"regex", "detector"}
_VALID_DETECTORS = {"email", "phone", "ssn", "credit_card", "ip"}
_VALID_TOKEN_MODES = {"tokenize", "encrypt"}


class ResponseTransformBase(BaseModel):
    backend_id: int | None = None
    backend_ids: list[int] | None = None
    priority: int = 0
    name: str
    enabled: bool = True
    transform_type: str
    content_types: str | None = None
    max_body_size: int = 1048576
    # replace / inject
    find_regex: str | None = None
    replace_string: str | None = None
    # inject mode
    inject_string: str | None = None
    inject_position: str | None = None
    # mask mode
    mask_mode: str | None = None
    detector: str | None = None
    token_mode: str | None = None
    token_prefix: str | None = None
    token_ttl: int | None = None
    encrypt_key_env: str | None = None
    detokenize_query: bool = False

    @field_validator("find_regex")
    @classmethod
    def _validate_regex(cls, v):
        if v is None or v == "":
            return v
        try:
            _re.compile(v)
        except _re.error as e:
            raise ValueError(f"Invalid regex: {e}")
        return v

    @model_validator(mode="after")
    def _validate_type_fields(self):
        tt = self.transform_type
        if tt is None:
            # Update mode: transform_type may be omitted; skip cross-field validation.
            return self
        if tt not in _VALID_TRANSFORM_TYPES:
            raise ValueError(f"transform_type must be one of {sorted(_VALID_TRANSFORM_TYPES)}")

        if tt == "replace":
            if not self.find_regex:
                raise ValueError("replace requires find_regex")
            if self.replace_string is None:
                raise ValueError("replace requires replace_string")
        elif tt == "inject":
            if not self.find_regex:
                raise ValueError("inject requires find_regex")
            if self.inject_string is None:
                raise ValueError("inject requires inject_string")
            if self.inject_position not in _VALID_INJECT_POSITIONS:
                raise ValueError(f"inject_position must be one of {sorted(_VALID_INJECT_POSITIONS)}")
        elif tt == "mask":
            if self.mask_mode not in _VALID_MASK_MODES:
                raise ValueError(f"mask_mode must be one of {sorted(_VALID_MASK_MODES)}")
            if self.mask_mode == "regex":
                if not self.find_regex:
                    raise ValueError("mask with mask_mode=regex requires find_regex")
            else:  # detector
                if self.detector not in _VALID_DETECTORS:
                    raise ValueError(f"detector must be one of {sorted(_VALID_DETECTORS)}")
            if self.token_mode not in _VALID_TOKEN_MODES:
                raise ValueError(f"token_mode must be one of {sorted(_VALID_TOKEN_MODES)}")
            if self.token_mode == "tokenize":
                if not self.token_prefix:
                    raise ValueError("tokenize requires token_prefix")
                if self.token_ttl is None or self.token_ttl <= 0:
                    raise ValueError("tokenize requires token_ttl > 0")
            else:  # encrypt
                if not self.encrypt_key_env:
                    raise ValueError("encrypt requires encrypt_key_env (env var name)")
                if not self.token_prefix:
                    raise ValueError("encrypt requires token_prefix")
        return self


class ResponseTransformCreate(ResponseTransformBase):
    pass


ResponseTransformUpdate = _optional_update(ResponseTransformBase)


class ResponseTransformResponse(ResponseTransformBase):
    id: int
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ResponseTransformReorder(BaseModel):
    ordered_ids: list[int]


class ResponseTransformValidateRequest(BaseModel):
    """A subset of ResponseTransformBase for live validation without saving."""

    transform_type: str
    find_regex: str | None = None
    replace_string: str | None = None
    inject_string: str | None = None
    inject_position: str | None = None
    mask_mode: str | None = None
    detector: str | None = None
    token_mode: str | None = None
    token_prefix: str | None = None
    token_ttl: int | None = None
    encrypt_key_env: str | None = None
    detokenize_query: bool | None = None


class ResponseTransformValidateResponse(BaseModel):
    valid: bool
    error: str | None = None


__all__ = [
    "ResponseTransformBase",
    "ResponseTransformCreate",
    "ResponseTransformUpdate",
    "ResponseTransformResponse",
    "ResponseTransformReorder",
    "ResponseTransformValidateRequest",
    "ResponseTransformValidateResponse",
]
