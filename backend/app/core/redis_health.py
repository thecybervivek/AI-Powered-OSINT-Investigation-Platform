import logging

from backend.app.core.config import settings

logger = logging.getLogger("app.core.redis_health")

# Kept short and independent of any request/business timeout: a
# readiness probe must return quickly even when Redis is completely
# unreachable (connection refused, black-holed network, etc.), so
# orchestrators get a timely, accurate signal rather than a hung check.
_HEALTH_CHECK_TIMEOUT_SECONDS = 2.0


def redis_is_required() -> bool:
    """
    Redis is only a REQUIRED dependency when something is actually
    configured to use it. Today that's RATE_LIMIT_BACKEND=="redis";
    if the app is running with the in-memory rate limiter, Redis being
    unreachable (or not deployed at all) must not affect readiness -
    dependency criticality is configuration-driven, not assumed.
    """

    return settings.RATE_LIMIT_BACKEND == "redis"


async def redis_health() -> bool:
    """
    Returns True if Redis answered PING within the timeout, False for
    any failure (connection refused, timeout, auth failure, etc.).
    Never raises - a health check that can itself crash the endpoint
    it's protecting defeats the purpose.
    """

    if not redis_is_required():
        return True

    try:
        import redis.asyncio as redis_asyncio
    except ImportError:
        logger.error(
            "RATE_LIMIT_BACKEND=redis but the 'redis' package is not "
            "installed - this is a deployment configuration error."
        )
        return False

    client = redis_asyncio.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD or None,
        db=settings.REDIS_DB,
        socket_connect_timeout=_HEALTH_CHECK_TIMEOUT_SECONDS,
        socket_timeout=_HEALTH_CHECK_TIMEOUT_SECONDS,
    )

    try:
        return bool(await client.ping())

    except Exception as error:
        logger.warning("Redis readiness check failed: %s", error)
        return False

    finally:
        await client.aclose()
