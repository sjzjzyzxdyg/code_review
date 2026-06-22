from app.core.config import settings


def ensure_storage_dirs() -> None:
    for path in (
        settings.storage_dir,
        settings.projects_dir,
        settings.reports_dir,
        settings.logs_dir,
    ):
        path.mkdir(parents=True, exist_ok=True)

