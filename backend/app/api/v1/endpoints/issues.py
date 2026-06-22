from fastapi import APIRouter

from app.schemas.issue import ReviewIssueRead
from app.services.issue_service import issue_service

router = APIRouter()


@router.get("", response_model=list[ReviewIssueRead])
def list_issues(task_id: str | None = None) -> list[ReviewIssueRead]:
    return issue_service.list_issues(task_id=task_id)


@router.get("/{issue_id}", response_model=ReviewIssueRead)
def get_issue(issue_id: str) -> ReviewIssueRead:
    return issue_service.get_issue(issue_id)

