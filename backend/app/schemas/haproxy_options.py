from pydantic import BaseModel, Field


class HaproxyOption(BaseModel):
    target: str = Field(default="section", pattern="^(section|bind)$")
    directive: str
    value: str
    enabled: bool = True


__all__ = ["HaproxyOption"]
