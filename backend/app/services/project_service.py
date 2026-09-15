import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

from fastapi import HTTPException, UploadFile, status

from app.core.config import settings
from app.core.db import Database, get_db
from app.schemas.project import ProjectCreate, ProjectCreateFromFiles, ProjectCreateFromPath, ProjectRead, ProjectTreeNode

logger = logging.getLogger(__name__)


class ProjectService:
    def __init__(self, db: Database | None = None) -> None:
        self._db = db or get_db()

    def _save(self, project: ProjectRead) -> ProjectRead:
        self._db.upsert(
            "projects", project.id, None,
            project.created_at.isoformat(), project.model_dump(mode="json"),
        )
        return project

    def create_project(self, payload: ProjectCreate) -> ProjectRead:
        now = datetime.utcnow()
        project = ProjectRead(
            id=str(uuid4()),
            name=payload.name,
            source_type=payload.source_type,
            repo_url=payload.repo_url,
            local_path=payload.local_path,
            created_at=now,
            updated_at=now,
        )
        return self._save(project)

    def create_project_from_path(self, payload: ProjectCreateFromPath) -> ProjectRead:
        path = Path(payload.path).resolve()
        self._ensure_within_allowed_roots(path)
        if not path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Path not found: {payload.path}",
            )
        if not path.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Path is not a directory: {payload.path}",
            )
        now = datetime.utcnow()
        project = ProjectRead(
            id=str(uuid4()),
            name=path.name,
            source_type="local",
            local_path=str(path),
            created_at=now,
            updated_at=now,
        )
        return self._save(project)

    def create_project_from_files(self, payload: ProjectCreateFromFiles) -> ProjectRead:
        files: list[Path] = []
        for raw in payload.paths:
            path = Path(raw).resolve()
            self._ensure_within_allowed_roots(path)
            if not path.exists():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"File not found: {raw}",
                )
            if not path.is_file():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Not a file: {raw}",
                )
            files.append(path)

        common = Path(os.path.commonpath([str(f) for f in files]))
        if common.is_file():
            common = common.parent

        project_id = str(uuid4())
        source_dir = settings.projects_dir / project_id / "source"
        source_dir.mkdir(parents=True, exist_ok=True)

        for file in files:
            try:
                rel = file.relative_to(common)
            except ValueError:
                rel = Path(file.name)
            dest = source_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, dest)

        now = datetime.utcnow()
        project = ProjectRead(
            id=project_id,
            name=common.name or "custom-selection",
            source_type="local",
            local_path=str(source_dir),
            created_at=now,
            updated_at=now,
        )
        return self._save(project)

    async def create_project_from_upload(self, file: UploadFile) -> ProjectRead:
        name = Path(file.filename or "uploaded-project").stem
        now = datetime.utcnow()
        project_id = str(uuid4())
        project_dir = settings.projects_dir / project_id
        project_dir.mkdir(parents=True, exist_ok=True)

        target_path = project_dir / (file.filename or "uploaded-project.zip")
        with target_path.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                output.write(chunk)

        if target_path.suffix.lower() == ".zip":
            source_dir = project_dir / "source"
            source_dir.mkdir(parents=True, exist_ok=True)
            self._safe_extract_zip(target_path, source_dir)
        else:
            source_dir = project_dir

        project = ProjectRead(
            id=project_id,
            name=name,
            source_type="upload",
            local_path=str(source_dir),
            created_at=now,
            updated_at=now,
        )
        return self._save(project)

    def list_projects(self) -> list[ProjectRead]:
        return [ProjectRead.model_validate(row) for row in self._db.list("projects")]

    def get_project(self, project_id: str) -> ProjectRead:
        row = self._db.get("projects", project_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )
        return ProjectRead.model_validate(row)

    def get_project_tree(self, project_id: str) -> list[ProjectTreeNode]:
        project = self.get_project(project_id)
        if not project.local_path:
            return []

        root = Path(project.local_path)
        if not root.exists() or not root.is_dir():
            return []

        return [self._build_tree_node(path, root) for path in sorted(root.iterdir())]

    def resolve_project_path(self, project_id: str, scan_scope: str = ".") -> Path:
        project = self.get_project(project_id)
        if not project.local_path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Project has no local path",
            )

        root = Path(project.local_path).resolve()
        target = (root / scan_scope).resolve()
        if root != target and root not in target.parents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan scope escapes project directory",
            )
        if not target.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan scope not found",
            )
        return target

    def _ensure_within_allowed_roots(self, path: Path) -> None:
        """Reject registration of a path outside the configured allowlist.

        No-op when CODE_REVIEW_ALLOWED_PROJECT_ROOTS is unset, preserving the
        default single-user local-tool behavior. Once this service is shared
        (e.g. on an internal network), configure the allowlist so registering
        a project can't be used to make the server read arbitrary files it
        happens to have access to.
        """
        roots = settings.allowed_project_roots
        if not roots:
            return
        for root in roots:
            try:
                path.relative_to(Path(root).resolve())
                return
            except ValueError:
                continue
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path is outside the allowed project roots.",
        )

    def _build_tree_node(self, path: Path, root: Path) -> ProjectTreeNode:
        relative_path = str(path.relative_to(root)).replace("\\", "/")
        if path.is_dir():
            children = [self._build_tree_node(child, root) for child in sorted(path.iterdir())]
            return ProjectTreeNode(
                name=path.name,
                path=relative_path,
                type="directory",
                children=children,
            )

        return ProjectTreeNode(name=path.name, path=relative_path, type="file")

    def _safe_extract_zip(self, zip_path: Path, target_dir: Path) -> None:
        try:
            with ZipFile(zip_path) as archive:
                total_uncompressed = 0
                for member in archive.infolist():
                    member_path = (target_dir / member.filename).resolve()
                    if target_dir.resolve() != member_path and target_dir.resolve() not in member_path.parents:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid zip path",
                        )
                    # Guard against zip bombs: absurd compression ratios or a
                    # decompressed payload far larger than the archive itself.
                    if (
                        member.compress_size > 0
                        and member.file_size / member.compress_size > settings.max_zip_compression_ratio
                    ):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Zip entry has a suspicious compression ratio",
                        )
                    total_uncompressed += member.file_size
                    if total_uncompressed > settings.max_upload_uncompressed_bytes:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Uncompressed archive contents exceed the allowed size limit",
                        )
                archive.extractall(target_dir)
        except BadZipFile as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is not a valid zip archive",
            ) from exc


project_service = ProjectService()
