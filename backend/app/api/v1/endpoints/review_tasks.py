from fastapi import APIRouter, BackgroundTasks, status

from app.schemas.review import ReviewTaskCreate, ReviewTaskRead
from app.services.review_service import review_service

router = APIRouter()


@router.post("", response_model=ReviewTaskRead, status_code=status.HTTP_201_CREATED)
def create_review_task(
    payload: ReviewTaskCreate,
    background_tasks: BackgroundTasks,
) -> ReviewTaskRead:
    task = review_service.create_task(payload)
    if payload.auto_start:
        background_tasks.add_task(review_service.run_task, task.id)
    return task


@router.get("", response_model=list[ReviewTaskRead])
def list_review_tasks() -> list[ReviewTaskRead]:
    return review_service.list_tasks()


@router.get("/{task_id}", response_model=ReviewTaskRead)
def get_review_task(task_id: str) -> ReviewTaskRead:
    return review_service.get_task(task_id)


@router.post("/{task_id}/cancel", response_model=ReviewTaskRead)
def cancel_review_task(task_id: str) -> ReviewTaskRead:
    return review_service.cancel_task(task_id)


@router.post("/{task_id}/run", response_model=ReviewTaskRead)
def run_review_task(task_id: str) -> ReviewTaskRead:
    return review_service.run_task(task_id)
