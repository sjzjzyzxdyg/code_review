import json
from datetime import datetime
from uuid import uuid4

from fastapi import HTTPException, status

from app.core.config import settings
from app.core.db import Database, get_db
from app.schemas.report import ReviewReportRead


class ReportService:
    def __init__(self, db: Database | None = None) -> None:
        self._db = db or get_db()

    def list_reports(self, task_id: str | None = None) -> list[ReviewReportRead]:
        rows = self._db.list("reports", parent_id=task_id)
        return [ReviewReportRead.model_validate(row) for row in rows]

    def create_report(
        self,
        task_id: str,
        markdown: str,
        json_payload: dict,
        summary: str,
    ) -> ReviewReportRead:
        report_id = str(uuid4())
        report_dir = settings.reports_dir / task_id
        report_dir.mkdir(parents=True, exist_ok=True)
        markdown_path = report_dir / f"{report_id}.md"
        json_path = report_dir / f"{report_id}.json"
        markdown_path.write_text(markdown, encoding="utf-8")
        json_path.write_text(
            json.dumps(json_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        report = ReviewReportRead(
            id=report_id,
            task_id=task_id,
            markdown_path=str(markdown_path),
            json_path=str(json_path),
            summary=summary,
            created_at=datetime.utcnow(),
        )
        self._db.upsert(
            "reports", report.id, task_id,
            report.created_at.isoformat(), report.model_dump(mode="json"),
        )
        return report

    def get_report(self, report_id: str) -> ReviewReportRead:
        row = self._db.get("reports", report_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Review report not found",
            )
        return ReviewReportRead.model_validate(row)


report_service = ReportService()
