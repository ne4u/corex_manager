from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class TaskResponse(BaseModel):
    id: int
    task_type: str
    status: str
    payload: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


__all__ = ["TaskResponse"]
