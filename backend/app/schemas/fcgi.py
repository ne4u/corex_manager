from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ._base import _optional_update


class FcgiParam(BaseModel):
    name: str
    value: str
    enabled: bool = True


class FcgiAppBase(BaseModel):
    name: str
    description: str | None = None
    docroot: str | None = None
    index: str | None = None
    path_info: str | None = None
    log_stderr_enabled: bool = False
    log_stderr_target: str | None = None
    keep_conn: bool = True
    mpxs_conns: bool = False
    max_reqs: int | None = Field(default=1, ge=1)
    params: list[FcgiParam] | None = []


class FcgiAppCreate(FcgiAppBase):
    pass


FcgiAppUpdate = _optional_update(FcgiAppBase)


class FcgiAppResponse(FcgiAppBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = ["FcgiAppBase", "FcgiAppCreate", "FcgiAppResponse", "FcgiAppUpdate", "FcgiParam"]
