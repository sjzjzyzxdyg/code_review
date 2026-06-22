from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


SourceType = Literal["upload", "git", "local"]


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    source_type: SourceType = "local"
    repo_url: str | None = None
    local_path: str | None = None


class ProjectRead(BaseModel):
    id: str
    name: str
    source_type: SourceType
    repo_url: str | None = None
    local_path: str | None = None
    created_at: datetime
    updated_at: datetime


class ProjectTreeNode(BaseModel):
    name: str
    path: str
    type: Literal["file", "directory"]
    children: list["ProjectTreeNode"] = Field(default_factory=list)
