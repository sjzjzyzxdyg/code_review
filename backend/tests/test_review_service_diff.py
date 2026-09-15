from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.core.db import Database
from app.schemas.issue import ReviewIssueRead
from app.schemas.review import ReviewTaskRead
from app.services.issue_service import issue_service
from app.services.review_service import ReviewService


def _issue(issue_id: str, task_id: str, file_path: str, line: int, rule_id: str) -> ReviewIssueRead:
    return ReviewIssueRead(
        id=issue_id, task_id=task_id, tool="cppcheck", rule_id=rule_id,
        file_path=file_path, line=line, issue_type=rule_id, risk_level="medium",
        description="d", reason="r", fix_suggestion="f", confidence=0.7,
        is_valid=True, created_at=datetime.utcnow(),
    )


def _task(task_id: str, project_id: str, created_at: datetime, completed: bool = True) -> ReviewTaskRead:
    return ReviewTaskRead(
        id=task_id, project_id=project_id, status="completed" if completed else "failed",
        scan_scope=".", rule_config={}, created_at=created_at,
    )


@pytest.fixture()
def wired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReviewService:
    db = Database(tmp_path / "test.db")
    service = ReviewService(db=db)
    monkeypatch.setattr(issue_service, "_db", db)
    return service


def test_diff_with_no_previous_task_returns_everything_as_new(wired: ReviewService) -> None:
    t0 = datetime(2024, 1, 1)
    wired._save(_task("t1", "proj-1", t0))
    issue_service.replace_task_issues("t1", [_issue("i1", "t1", "a.cpp", 1, "ruleA")])

    diff = wired.get_task_diff("t1")

    assert diff.previous_task_id is None
    assert [i.id for i in diff.new_issues] == ["i1"]
    assert diff.resolved_issues == []
    assert diff.unchanged_count == 0


def test_diff_reports_new_resolved_and_unchanged(wired: ReviewService) -> None:
    t0 = datetime(2024, 1, 1)
    t1 = t0 + timedelta(days=1)
    wired._save(_task("t1", "proj-1", t0))
    issue_service.replace_task_issues("t1", [
        _issue("i1", "t1", "a.cpp", 1, "ruleA"),   # will persist into t2
        _issue("i2", "t1", "b.cpp", 2, "ruleB"),   # will be resolved by t2
    ])
    wired._save(_task("t2", "proj-1", t1))
    issue_service.replace_task_issues("t2", [
        _issue("i3", "t2", "a.cpp", 1, "ruleA"),   # same (file,line,rule) as i1
        _issue("i4", "t2", "c.cpp", 3, "ruleC"),   # brand new
    ])

    diff = wired.get_task_diff("t2")

    assert diff.previous_task_id == "t1"
    assert [i.id for i in diff.new_issues] == ["i4"]
    assert [i.id for i in diff.resolved_issues] == ["i2"]
    assert diff.unchanged_count == 1


def test_diff_ignores_non_completed_and_later_tasks(wired: ReviewService) -> None:
    t0 = datetime(2024, 1, 1)
    t1 = t0 + timedelta(days=1)
    t2 = t0 + timedelta(days=2)
    wired._save(_task("failed", "proj-1", t0, completed=False))
    issue_service.replace_task_issues("failed", [_issue("if1", "failed", "x.cpp", 1, "ruleX")])
    wired._save(_task("current", "proj-1", t1))
    wired._save(_task("future", "proj-1", t2))  # must not be picked as "previous"

    diff = wired.get_task_diff("current")

    assert diff.previous_task_id is None
