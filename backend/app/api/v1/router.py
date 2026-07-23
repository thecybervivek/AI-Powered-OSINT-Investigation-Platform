from fastapi import APIRouter

from backend.app.api.v1.endpoints.auth import router as auth_router
from backend.app.api.v1.endpoints.domain import router as domain_router
from backend.app.api.v1.endpoints.email import router as email_router
from backend.app.api.v1.endpoints.health import router as health_router
from backend.app.api.v1.endpoints.username import router as username_router

api_router = APIRouter()

# ==========================================================
# Health Endpoints
# ==========================================================

api_router.include_router(
    health_router,
    prefix="/health",
    tags=["Health"],
)

# ==========================================================
# Authentication Endpoints
# ==========================================================

api_router.include_router(
    auth_router,
    tags=["Authentication"],
)

# ==========================================================
# Username Intelligence Endpoints (Milestone 2)
# ==========================================================

api_router.include_router(
    username_router,
    prefix="/investigations/username",
    tags=["Username Intelligence"],
)

# ==========================================================
# Email Intelligence Endpoints (Milestone 3)
# ==========================================================

api_router.include_router(
    email_router,
    prefix="/investigations/email",
    tags=["Email Intelligence"],
)

# ==========================================================
# Domain / IP / DNS Intelligence Endpoints (Milestone 4)
# ==========================================================

api_router.include_router(
    domain_router,
    prefix="/investigations/domain",
    tags=["Domain Intelligence"],
)