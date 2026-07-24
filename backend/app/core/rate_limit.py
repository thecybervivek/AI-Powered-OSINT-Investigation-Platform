from jose import JWTError
from jose import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from backend.app.core.config import settings


def _build_storage_uri() -> str:
    """
    Resolves the slowapi `storage_uri` from RATE_LIMIT_BACKEND.

    "memory" -> in-process storage (this milestone). No external
    service required, but limits are per-process and reset on restart -
    fine for a single-instance deployment, not for multiple workers.

    "redis" -> reuses the REDIS_* settings already present in config.py
    since Milestone 1. This branch is intentionally NOT exercised in
    Milestone 5 (no Redis instance is stood up here) - it exists so a
    future milestone can flip RATE_LIMIT_BACKEND to "redis" without any
    endpoint, decorator, or Limiter-call-site changes.
    """

    if settings.RATE_LIMIT_BACKEND == "redis":

        auth = f":{settings.REDIS_PASSWORD}@" if settings.REDIS_PASSWORD else ""
        return f"redis://{auth}{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"

    return "memory://"


def _rate_limit_key(request: Request) -> str:
    """
    Keys rate limits per authenticated user when a valid bearer token is
    present, so one user can't exhaust another's quota behind a shared
    NAT/proxy IP. Falls back to client IP for unauthenticated requests
    (e.g. before login). This is a best-effort read of the token purely
    for bucketing - it does NOT replace get_current_user's real
    validation, and any decode failure silently falls back to IP.
    """

    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):

        token = auth_header.removeprefix("Bearer ")

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
            user_id = payload.get("sub")

            if user_id:
                return f"user:{user_id}"

        except JWTError:
            pass

    return f"ip:{get_remote_address(request)}"


limiter = Limiter(
    key_func=_rate_limit_key,
    storage_uri=_build_storage_uri(),
    default_limits=[settings.RATE_LIMIT_DEFAULT] if settings.RATE_LIMIT_ENABLED else [],
    enabled=settings.RATE_LIMIT_ENABLED,
)
