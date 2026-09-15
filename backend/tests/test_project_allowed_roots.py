from pathlib import Path

import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.services.project_service import ProjectService


def test_ensure_within_allowed_roots_noop_when_unconfigured(tmp_path: Path) -> None:
    service = ProjectService()
    assert settings.allowed_project_roots == []

    service._ensure_within_allowed_roots(tmp_path / "anything")  # must not raise


def test_ensure_within_allowed_roots_allows_path_inside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProjectService()
    allowed = tmp_path / "workspace"
    allowed.mkdir()
    target = allowed / "project-a"
    monkeypatch.setattr(settings, "allowed_project_roots", [str(allowed)])

    service._ensure_within_allowed_roots(target.resolve())  # must not raise


def test_ensure_within_allowed_roots_blocks_path_outside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProjectService()
    allowed = tmp_path / "workspace"
    allowed.mkdir()
    outside = tmp_path / "elsewhere" / "secret"
    monkeypatch.setattr(settings, "allowed_project_roots", [str(allowed)])

    with pytest.raises(HTTPException) as exc_info:
        service._ensure_within_allowed_roots(outside.resolve())
    assert exc_info.value.status_code == 403
