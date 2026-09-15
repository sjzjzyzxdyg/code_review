from pathlib import Path

import pytest

from app.core.config import settings
from app.core.db import Database
from app.schemas.review import ReviewTaskCreate
from app.services import review_service as review_service_module
from app.services.issue_service import issue_service
from app.services.report_service import report_service
from app.services.suppression_service import suppression_service


class _FakeProject:
    def __init__(self, project_id: str, local_path: str) -> None:
        self.id = project_id
        self.local_path = local_path


class _FakeProjectService:
    def __init__(self, project: _FakeProject) -> None:
        self._project = project

    def get_project(self, project_id: str) -> _FakeProject:
        return self._project

    def resolve_project_path(self, project_id: str, scan_scope: str = ".") -> Path:
        return Path(self._project.local_path)


def _wire_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scan_dir: Path) -> "review_service_module.ReviewService":
    test_db = Database(tmp_path / "test.db")
    service = review_service_module.ReviewService(db=test_db)

    project = _FakeProject("proj-1", str(scan_dir))
    monkeypatch.setattr(review_service_module, "project_service", _FakeProjectService(project))
    monkeypatch.setattr(issue_service, "_db", test_db)
    monkeypatch.setattr(report_service, "_db", test_db)
    monkeypatch.setattr(suppression_service, "_db", test_db)
    monkeypatch.setattr(settings, "reports_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "llm_enabled", False)

    monkeypatch.setattr(service.clang_analyzer_tool, "run", lambda *a, **k: [])
    monkeypatch.setattr(service.clang_custom_checker, "run", lambda *a, **k: [])
    monkeypatch.setattr(service.cross_file_checker, "run", lambda *a, **k: [])
    monkeypatch.setattr(service.taint_flow_agent, "run", lambda *a, **k: [])

    return service


def test_run_task_end_to_end_produces_issues_and_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_dir = tmp_path / "project"
    scan_dir.mkdir()
    src = scan_dir / "main.cpp"
    src.write_text("int main() { return 0; }")

    service = _wire_service(tmp_path, monkeypatch, scan_dir)
    monkeypatch.setattr(service.cppcheck_tool, "run", lambda *a, **k: [{
        "tool": "cppcheck", "rule_id": "nullPointer", "severity": "error",
        "message": "boom", "file_path": str(src), "line": 1, "column": 1,
    }])

    task = service.create_task(ReviewTaskCreate(project_id="proj-1"))
    finished = service.run_task(task.id)

    assert finished.status == "completed"
    assert finished.error_message is None

    issues = issue_service.list_issues(task_id=task.id)
    assert len(issues) == 1
    assert issues[0].rule_id == "nullPointer"
    assert issues[0].file_path == "main.cpp"
    # LLM disabled -> falls back to static severity rather than aborting the task.
    assert issues[0].risk_level == "high"

    reports = report_service.list_reports(task_id=task.id)
    assert len(reports) == 1
    assert Path(reports[0].markdown_path).exists()


def test_run_task_propagates_tool_unavailable_as_failed_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tools.cppcheck_tool import StaticAnalysisToolUnavailable

    scan_dir = tmp_path / "project"
    scan_dir.mkdir()

    service = _wire_service(tmp_path, monkeypatch, scan_dir)

    def raise_unavailable(*a, **k):
        raise StaticAnalysisToolUnavailable("Cppcheck is not installed or not available in PATH.")

    monkeypatch.setattr(service.cppcheck_tool, "run", raise_unavailable)

    task = service.create_task(ReviewTaskCreate(project_id="proj-1"))
    finished = service.run_task(task.id)

    assert finished.status == "failed"
    assert "Cppcheck" in finished.error_message


def test_run_task_respects_false_positive_suppression(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_dir = tmp_path / "project"
    scan_dir.mkdir()
    src = scan_dir / "main.cpp"
    src.write_text("int main() { return 0; }")

    service = _wire_service(tmp_path, monkeypatch, scan_dir)
    monkeypatch.setattr(service.cppcheck_tool, "run", lambda *a, **k: [{
        "tool": "cppcheck", "rule_id": "nullPointer", "severity": "error",
        "message": "boom", "file_path": str(src), "line": 1, "column": 1,
    }])

    # A prior scan's finding at this exact (file, rule, line) was marked a false positive.
    suppression_service.suppress("proj-1", "main.cpp", "nullPointer", 1)

    task = service.create_task(ReviewTaskCreate(project_id="proj-1"))
    service.run_task(task.id)

    assert issue_service.list_issues(task_id=task.id) == []


def test_incremental_rescan_skips_unchanged_files_and_reuses_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_dir = tmp_path / "project"
    scan_dir.mkdir()
    stable = scan_dir / "stable.cpp"
    stable.write_text("void stable() {}")
    evolving = scan_dir / "evolving.cpp"
    evolving.write_text("void evolving() {}")

    service = _wire_service(tmp_path, monkeypatch, scan_dir)
    calls: list[list[Path] | None] = []

    def fake_cppcheck_run(project_path, **kwargs):
        target_files = kwargs.get("target_files")
        calls.append(target_files)
        if target_files is None:
            return [
                {"tool": "cppcheck", "rule_id": "styleIssue", "severity": "style",
                 "message": "m1", "file_path": str(stable), "line": 1, "column": 1},
                {"tool": "cppcheck", "rule_id": "styleIssue", "severity": "style",
                 "message": "m2", "file_path": str(evolving), "line": 1, "column": 1},
            ]
        assert [Path(f).resolve() for f in target_files] == [evolving.resolve()]
        return [{
            "tool": "cppcheck", "rule_id": "newIssue", "severity": "error",
            "message": "m3", "file_path": str(evolving), "line": 2, "column": 1,
        }]

    monkeypatch.setattr(service.cppcheck_tool, "run", fake_cppcheck_run)

    task1 = service.create_task(ReviewTaskCreate(project_id="proj-1"))
    service.run_task(task1.id)
    issues1 = {i.rule_id for i in issue_service.list_issues(task_id=task1.id)}
    assert issues1 == {"styleIssue"}
    assert calls[0] is None  # first run: no cache yet, full scan

    evolving.write_text("void evolving() { int x = 1; }")

    task2 = service.create_task(ReviewTaskCreate(project_id="proj-1"))
    service.run_task(task2.id)

    assert calls[1] is not None  # second run: only the changed file was rescanned
    issues2 = {i.rule_id for i in issue_service.list_issues(task_id=task2.id)}
    assert issues2 == {"styleIssue", "newIssue"}
