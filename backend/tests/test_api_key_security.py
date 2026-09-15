import asyncio

import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.security import require_api_key


def test_require_api_key_noop_when_unset() -> None:
    assert settings.api_key is None
    asyncio.run(require_api_key(x_api_key=None))  # must not raise


def test_require_api_key_rejects_missing_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "api_key", "secret-token")

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(require_api_key(x_api_key=None))
    assert exc_info.value.status_code == 401


def test_require_api_key_rejects_wrong_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "api_key", "secret-token")

    with pytest.raises(HTTPException):
        asyncio.run(require_api_key(x_api_key="wrong"))


def test_require_api_key_accepts_matching_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "api_key", "secret-token")

    asyncio.run(require_api_key(x_api_key="secret-token"))  # must not raise
