from pydantic import BaseModel, ConfigDict

from ._base import _optional_update


class CustomErrorPageBase(BaseModel):
    listener_id: int | None = None
    listener_ids: list[int] | None = None
    code: int
    content_type: str = "text/html"
    content: str


class CustomErrorPageCreate(CustomErrorPageBase):
    pass


CustomErrorPageUpdate = _optional_update(CustomErrorPageBase)


class CustomErrorPageResponse(CustomErrorPageBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class CustomErrorPagePreview(BaseModel):
    content: str
    content_type: str = "text/html"


__all__ = [
    "CustomErrorPageBase",
    "CustomErrorPageCreate",
    "CustomErrorPagePreview",
    "CustomErrorPageResponse",
    "CustomErrorPageUpdate",
]
