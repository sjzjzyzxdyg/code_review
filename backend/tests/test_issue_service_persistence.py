from datetime import datetime
from pathlib import Path

from app.core.db import Database
from app.schemas.issue import ReviewIssueRead
from app.services.issue_service import IssueService


def _make_issue(issue_id: str, task_id: str) -> ReviewIssueRead:
    return ReviewIssueRead(
        id=issue_id,
        task_id=task_id,
        tool="cppcheck",
        rule_id="nullPointer",
        file_path="src/main.cpp",
        line=10,
        issue_type="nullPointer",
        risk_level="high",
        description="desc",
        reason="reason",
        fix_suggestion="fix",
        confidence=0.8,
        is_valid=True,
        created_at=datetime.utcnow(),
    )


def test_replace_task_issues_then_list_and_get(tmp_path: Path) -> None:
    service = IssueService(db=Database(tmp_path / "test.db"))
    issue = _make_issue("i1", "task-a")

    service.replace_task_issues("task-a", [issue])

    assert [i.id for i in service.list_issues(task_id="task-a")] == ["i1"]
    assert service.get_issue("i1").file_path == "src/main.cpp"


def test_replace_task_issues_drops_stale_issues_for_same_task(tmp_path: Path) -> None:
    service = IssueService(db=Database(tmp_path / "test.db"))
    service.replace_task_issues("task-a", [_make_issue("old", "task-a")])

    service.replace_task_issues("task-a", [_make_issue("new", "task-a")])

    ids = [i.id for i in service.list_issues(task_id="task-a")]
    assert ids == ["new"]


def test_replace_task_issues_does_not_touch_other_tasks(tmp_path: Path) -> None:
    service = IssueService(db=Database(tmp_path / "test.db"))
    service.replace_task_issues("task-a", [_make_issue("a1", "task-a")])
    service.replace_task_issues("task-b", [_make_issue("b1", "task-b")])

    service.replace_task_issues("task-a", [_make_issue("a2", "task-a")])

    assert [i.id for i in service.list_issues(task_id="task-b")] == ["b1"]


def test_issues_survive_service_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    original = IssueService(db=Database(db_path))
    original.replace_task_issues("task-a", [_make_issue("i1", "task-a")])

    restarted = IssueService(db=Database(db_path))

    assert [i.id for i in restarted.list_issues(task_id="task-a")] == ["i1"]


def test_mark_false_positive_flips_is_valid_and_persists(tmp_path: Path) -> None:
    service = IssueService(db=Database(tmp_path / "test.db"))
    service.replace_task_issues("task-a", [_make_issue("i1", "task-a")])

    updated = service.mark_false_positive("i1")

    assert updated.is_valid is False
    assert service.get_issue("i1").is_valid is False
