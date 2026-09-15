from pathlib import Path

import pytest
from fastapi import HTTPException

from app.core.db import Database
from app.schemas.project import ProjectCreate
from app.services.project_service import ProjectService


def test_created_project_is_retrievable(tmp_path: Path) -> None:
    service = ProjectService(db=Database(tmp_path / "test.db"))

    project = service.create_project(ProjectCreate(name="demo"))

    fetched = service.get_project(project.id)
    assert fetched.id == project.id
    assert fetched.name == "demo"
    assert project in service.list_projects()


def test_get_project_missing_raises_404(tmp_path: Path) -> None:
    service = ProjectService(db=Database(tmp_path / "test.db"))

    with pytest.raises(HTTPException) as exc_info:
        service.get_project("does-not-exist")
    assert exc_info.value.status_code == 404


def test_project_survives_service_restart(tmp_path: Path) -> None:
    """A new ProjectService instance backed by the same DB file (simulating a
    process restart) must still see projects created before the restart."""
    db_path = tmp_path / "test.db"
    original = ProjectService(db=Database(db_path))
    project = original.create_project(ProjectCreate(name="demo"))

    restarted = ProjectService(db=Database(db_path))

    fetched = restarted.get_project(project.id)
    assert fetched.name == "demo"
