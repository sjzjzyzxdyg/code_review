from datetime import datetime
from typing import Any
from typing import Literal

from pydantic import BaseModel, Field


RiskLevel = Literal["low", "medium", "high", "critical"]


class ReviewIssueRead(BaseModel):
    id: str
    task_id: str
    tool: str
    rule_id: str | None = None
    file_path: str
    line: int = Field(ge=1)
    column: int | None = None
    issue_type: str
    risk_level: RiskLevel
    description: str
    reason: str
    fix_suggestion: str
    confidence: float = Field(ge=0, le=1)
    is_valid: bool
    call_chain: list[str] = Field(default_factory=list)
    call_chain_graph: dict[str, Any] = Field(default_factory=dict)
    ast_summary: str | None = None
    ast_context: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    code_snippet: str | None = None
    created_at: datetime
