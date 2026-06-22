from fastapi import APIRouter, UploadFile, status

from app.schemas.project import ProjectCreate, ProjectRead, ProjectTreeNode
from app.services.project_service import project_service

router = APIRouter()


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate) -> ProjectRead:
    return project_service.create_project(payload)


@router.post("/upload", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
async def upload_project(file: UploadFile) -> ProjectRead:
    return await project_service.create_project_from_upload(file)


@router.get("", response_model=list[ProjectRead])
def list_projects() -> list[ProjectRead]:
    return project_service.list_projects()


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: str) -> ProjectRead:
    return project_service.get_project(project_id)


@router.get("/{project_id}/tree", response_model=list[ProjectTreeNode])
def get_project_tree(project_id: str) -> list[ProjectTreeNode]:
    return project_service.get_project_tree(project_id)

