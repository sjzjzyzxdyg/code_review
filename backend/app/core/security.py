from fastapi import Header, HTTPException, status

from app.core.config import settings


async def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """Reject the request unless it carries a matching X-API-Key header.

    A no-op when `settings.api_key` is unset, so a single-user local
    deployment keeps working with zero configuration. Set CODE_REVIEW_API_KEY
    once this service is reachable by more than one trusted user (e.g. shared
    on an internal network), since project registration can otherwise make
    the server read arbitrary files it has access to on behalf of anyone who
    can reach the API.
    """
    if not settings.api_key:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key",
        )
