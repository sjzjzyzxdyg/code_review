from datetime import datetime
from pathlib import Path
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

from fastapi import HTTPException, UploadFile, status

from app.core.config import settings
from app.schemas.project import ProjectCreate, ProjectRead, ProjectTreeNode


class ProjectService:
    def __init__(self) -> None:
        self._projects: dict[str, ProjectRead] = {}

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
        self._projects[project.id] = project
        return project

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
        self._projects[project.id] = project
        return project

    def list_projects(self) -> list[ProjectRead]:
        return list(self._projects.values())

    def get_project(self, project_id: str) -> ProjectRead:
        project = self._projects.get(project_id)
        if project is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )
        return project

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
                for member in archive.infolist():
                    member_path = (target_dir / member.filename).resolve()
                    if target_dir.resolve() != member_path and target_dir.resolve() not in member_path.parents:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid zip path",
                        )
                archive.extractall(target_dir)
        except BadZipFile as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is not a valid zip archive",
            ) from exc


project_service = ProjectService()
