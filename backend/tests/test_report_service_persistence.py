from pathlib import Path

import pytest

from app.core.config import settings
from app.core.db import Database
from app.services.report_service import ReportService


def test_create_report_then_list_and_get(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "reports_dir", tmp_path / "reports")
    service = ReportService(db=Database(tmp_path / "test.db"))

    report = service.create_report("task-a", "# report", {"issues": []}, "summary text")

    assert [r.id for r in service.list_reports(task_id="task-a")] == [report.id]
    assert service.get_report(report.id).summary == "summary text"


def test_reports_survive_service_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "reports_dir", tmp_path / "reports")
    db_path = tmp_path / "test.db"
    original = ReportService(db=Database(db_path))
    report = original.create_report("task-a", "# report", {}, "summary")

    restarted = ReportService(db=Database(db_path))

    assert restarted.get_report(report.id).task_id == "task-a"
