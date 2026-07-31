from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.core.logging_config import configure_logging
from backend.app.core.rate_limit import limiter
from backend.app.core.redis_health import redis_health
from backend.app.core.redis_health import redis_is_required
from backend.app.core.startup_checks import StartupDependencyError
from backend.app.core.startup_checks import verify_startup_dependencies
from backend.app.db.database import database_health
from backend.app.middleware.logging_middleware import RequestLoggingMiddleware
from backend.app.middleware.security_headers import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(debug=settings.DEBUG)

    print("=" * 60)
    print(f"Starting {settings.APP_NAME}")
    print(f"Environment : {settings.ENVIRONMENT}")
    print(f"Version     : {settings.APP_VERSION}")
    print("=" * 60)

    try:
        verify_startup_dependencies()

    except StartupDependencyError as error:
        # Fail fast and loud: a clear, actionable message on stdout/
        # stderr (visible in `docker logs` even before any log
        # aggregation is wired up) plus the structured logger, then
        # stop the process rather than accept traffic it can't serve.
        print("=" * 60)
        print("STARTUP ABORTED - a required dependency check failed:")
        print(str(error))
        print("=" * 60)
        raise

    # Database schema is managed by Alembic migrations.
    # Do NOT call Base.metadata.create_all() in production.

    yield

    print("=" * 60)
    print(f"Stopping {settings.APP_NAME}")
    print("=" * 60)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs" if settings.ENABLE_API_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_API_DOCS else None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# Rate Limiting (Milestone 5)
# ==========================================================
# app.state.limiter is the attribute slowapi's internals look up on
# every request; the exception handler turns an exceeded limit into a
# clean 429 JSON response instead of an unhandled error.

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Middleware executes bottom-up relative to add_middleware() calls, so
# SecurityHeadersMiddleware (added last) runs first on the request path.
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/", tags=["Home"])
async def home():
    return {
        "success": True,
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "message": "Welcome to AI Powered OSINT Investigation Platform",
    }


@app.get("/health", tags=["Health"])
async def health():
    """Liveness probe: proves the application process is serving requests."""
    return {"status": "healthy", "application": settings.APP_NAME, "version": settings.APP_VERSION}


@app.get("/ready", tags=["Health"])
async def ready():
    """
    Readiness probe: continuously evaluates required runtime
    dependencies. Database is always required. Redis is only required
    when something is actually configured to depend on it (currently
    RATE_LIMIT_BACKEND=="redis") - an unconfigured/optional dependency
    being unavailable must not make the whole application unready.
    """

    db_ok = database_health()
    redis_required = redis_is_required()
    redis_reachable = await redis_health()

    if not redis_required:
        redis_status = "not_configured"
    elif redis_reachable:
        redis_status = "ready"
    else:
        redis_status = "unavailable"

    checks = {
        "database": "ready" if db_ok else "unavailable",
        "redis": redis_status,
    }

    is_ready = db_ok and (redis_reachable or not redis_required)

    if not is_ready:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", **checks},
        )

    return {"status": "ready", **checks}


@app.get("/ping", tags=["Health"])
async def ping():
    return JSONResponse(
        status_code=200,
        content={
            "message": "pong",
        },
    )


app.include_router(
    api_router,
    prefix=settings.API_PREFIX,
)