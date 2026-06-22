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

    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    llm_enabled: bool = False
    llm_api_key: str | None = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: int = 30

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
