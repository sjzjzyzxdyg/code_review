import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.services.project_service import ProjectService


def _make_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def test_safe_extract_zip_allows_normal_archive(tmp_path: Path) -> None:
    service = ProjectService()
    zip_path = tmp_path / "project.zip"
    _make_zip(zip_path, {"src/main.cpp": b"int main() { return 0; }"})
    target_dir = tmp_path / "out"
    target_dir.mkdir()

    service._safe_extract_zip(zip_path, target_dir)

    assert (target_dir / "src" / "main.cpp").exists()


def test_safe_extract_zip_blocks_path_traversal(tmp_path: Path) -> None:
    service = ProjectService()
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../../escape.txt", b"pwned")
    target_dir = tmp_path / "out"
    target_dir.mkdir()

    with pytest.raises(HTTPException):
        service._safe_extract_zip(zip_path, target_dir)


def test_safe_extract_zip_blocks_zip_bomb_ratio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = ProjectService()
    zip_path = tmp_path / "bomb.zip"
    # Highly compressible payload well past the configured suppression ratio.
    _make_zip(zip_path, {"data.bin": b"0" * (10 * 1024 * 1024)})
    target_dir = tmp_path / "out"
    target_dir.mkdir()

    from app.core.config import settings
    monkeypatch.setattr(settings, "max_zip_compression_ratio", 10)

    with pytest.raises(HTTPException):
        service._safe_extract_zip(zip_path, target_dir)


def test_safe_extract_zip_blocks_oversized_uncompressed_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProjectService()
    zip_path = tmp_path / "large.zip"
    _make_zip(zip_path, {"data.bin": b"random-ish-data" * 1000})
    target_dir = tmp_path / "out"
    target_dir.mkdir()

    from app.core.config import settings
    monkeypatch.setattr(settings, "max_upload_uncompressed_bytes", 10)
    monkeypatch.setattr(settings, "max_zip_compression_ratio", 10_000_000)

    with pytest.raises(HTTPException):
        service._safe_extract_zip(zip_path, target_dir)
