from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


ReviewStatus = Literal[
    "created",
    "static_analyzing",
    "llm_reviewing",
    "result_validating",
    "report_generating",
    "completed",
    "failed",
    "cancelled",
]


class ReviewTaskCreate(BaseModel):
    project_id: str
    scan_scope: str = "."
    rule_config: dict[str, Any] = Field(default_factory=dict)
    auto_start: bool = True


class ReviewTaskRead(BaseModel):
    id: str
    project_id: str
    status: ReviewStatus
    scan_scope: str
    rule_config: dict[str, Any]
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
