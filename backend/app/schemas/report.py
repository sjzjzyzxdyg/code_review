from datetime import datetime

from pydantic import BaseModel


class ReviewReportRead(BaseModel):
    id: str
    task_id: str
    markdown_path: str | None = None
    json_path: str | None = None
    html_path: str | None = None
    summary: str
    created_at: datetime

