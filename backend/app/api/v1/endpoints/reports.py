from fastapi import APIRouter

from app.schemas.report import ReviewReportRead
from app.services.report_service import report_service

router = APIRouter()


@router.get("", response_model=list[ReviewReportRead])
def list_reports(task_id: str | None = None) -> list[ReviewReportRead]:
    return report_service.list_reports(task_id=task_id)


@router.get("/{report_id}", response_model=ReviewReportRead)
def get_report(report_id: str) -> ReviewReportRead:
    return report_service.get_report(report_id)

