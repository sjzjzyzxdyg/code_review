from fastapi import APIRouter

from app.schemas.issue import ReviewIssueRead
from app.services.issue_service import issue_service
from app.services.review_service import review_service
from app.services.suppression_service import suppression_service

router = APIRouter()


@router.get("", response_model=list[ReviewIssueRead])
def list_issues(task_id: str | None = None) -> list[ReviewIssueRead]:
    return issue_service.list_issues(task_id=task_id)


@router.get("/{issue_id}", response_model=ReviewIssueRead)
def get_issue(issue_id: str) -> ReviewIssueRead:
    return issue_service.get_issue(issue_id)


@router.post("/{issue_id}/false-positive", response_model=ReviewIssueRead)
def mark_issue_false_positive(issue_id: str) -> ReviewIssueRead:
    """Mark an issue as a false positive and suppress the same finding
    (same project/file/rule/line) in future scans of this project."""
    issue = issue_service.get_issue(issue_id)
    task = review_service.get_task(issue.task_id)
    suppression_service.suppress(task.project_id, issue.file_path, issue.rule_id, issue.line)
    return issue_service.mark_false_positive(issue_id)

