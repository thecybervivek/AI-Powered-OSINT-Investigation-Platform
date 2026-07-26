from fastapi import APIRouter

from backend.app.api.v1.endpoints.auth import router as auth_router
from backend.app.api.v1.endpoints.domain import router as domain_router
from backend.app.api.v1.endpoints.email import router as email_router
from backend.app.api.v1.endpoints.file import router as file_router
from backend.app.api.v1.endpoints.report import router as report_router
from backend.app.api.v1.endpoints.investigation import router as investigation_router
from backend.app.api.v1.endpoints.health import router as health_router
from backend.app.api.v1.endpoints.ioc import router as ioc_router
from backend.app.api.v1.endpoints.ip import router as ip_router
from backend.app.api.v1.endpoints.url import router as url_router
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
# Investigation History Endpoints (cross-module list/get/delete)
# ==========================================================

api_router.include_router(
    investigation_router,
    prefix="/investigations",
    tags=["Investigation History"],
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

# ==========================================================
# IP Intelligence Endpoints (Milestone 5)
# ==========================================================

api_router.include_router(
    ip_router,
    prefix="/investigations/ip",
    tags=["IP Intelligence"],
)

# ==========================================================
# URL Intelligence Endpoints (Milestone 5)
# ==========================================================

api_router.include_router(
    url_router,
    prefix="/investigations/url",
    tags=["URL Intelligence"],
)

# ==========================================================
# IOC Analysis Endpoints (Milestone 5)
# ==========================================================

api_router.include_router(
    ioc_router,
    prefix="/investigations/ioc",
    tags=["IOC Analysis"],
)
# ==========================================================
# File Intelligence Endpoints (Milestone 6)
# ==========================================================

api_router.include_router(
    file_router,
    prefix="/investigations/file",
    tags=["File Intelligence"],
)

# ==========================================================
# Report Endpoints (Milestone 7)
# ==========================================================

api_router.include_router(
    report_router,
    prefix="/reports",
    tags=["AI Investigation Reports"],
)
