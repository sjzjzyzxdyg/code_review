from fastapi import APIRouter

from app.api.v1.endpoints import health, issues, projects, reports, review_tasks

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(projects.router, prefix="/projects", tags=["projects"])
api_router.include_router(review_tasks.router, prefix="/review-tasks", tags=["review-tasks"])
api_router.include_router(issues.router, prefix="/issues", tags=["issues"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])

