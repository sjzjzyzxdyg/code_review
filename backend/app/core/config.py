from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Code Review Platform"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"
    debug: bool = False

    storage_dir: Path = Field(default=Path("storage"))
    projects_dir: Path = Field(default=Path("storage/projects"))
    reports_dir: Path = Field(default=Path("storage/reports"))
    logs_dir: Path = Field(default=Path("storage/logs"))
    database_path: Path = Field(default=Path("storage/app.db"))

    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    llm_enabled: bool = False
    llm_api_key: str | None = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "deepseek-v4-flash"
    llm_timeout_seconds: int = 30
    # How many single-path findings the review agent verifies per scan. Findings
    # beyond this are kept with their detector verdict, never dropped.
    llm_max_reviews: int = 40

    # Hard cap on any external static-analysis subprocess (cppcheck/clang/...)
    # so a pathological input can't hang a detection worker thread forever.
    tool_timeout_seconds: int = 120

    # Guardrails for uploaded zip archives.
    max_upload_uncompressed_bytes: int = 500 * 1024 * 1024  # 500 MB
    max_zip_compression_ratio: int = 100

    # When non-empty, /projects/from-path and /projects/from-files only accept
    # paths under one of these directories. Empty (default) keeps the current
    # single-user local-tool behavior of allowing any local path.
    allowed_project_roots: list[str] = []

    # When set, every /api/v1 request (except /health) must send a matching
    # `X-API-Key` header. Empty (default) keeps auth disabled for local use.
    api_key: str | None = None

    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CODE_REVIEW_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
