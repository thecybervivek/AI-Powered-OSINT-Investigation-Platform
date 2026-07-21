from fastapi import APIRouter

from backend.app.api.v1.endpoints.auth import router as auth_router
from backend.app.api.v1.endpoints.health import router as health_router

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