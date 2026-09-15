from fastapi import APIRouter, Depends

from app.api.v1.endpoints import health, issues, projects, reports, review_tasks
from app.core.security import require_api_key

api_router = APIRouter()
# Health check stays open (unauthenticated) so it can be used for liveness probes.
api_router.include_router(health.router, tags=["health"])

_protected = APIRouter(dependencies=[Depends(require_api_key)])
_protected.include_router(projects.router, prefix="/projects", tags=["projects"])
_protected.include_router(review_tasks.router, prefix="/review-tasks", tags=["review-tasks"])
_protected.include_router(issues.router, prefix="/issues", tags=["issues"])
_protected.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(_protected)

