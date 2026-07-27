from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi import status

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import get_current_user
from backend.app.core.rate_limit import limiter
from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.schemas.dns_intelligence import DNSIntelligenceRequest
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.services.dns_intelligence_service import DNSIntelligenceService

router = APIRouter()


# ==========================================================
# Run DNS Intelligence Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def investigate_dns_intelligence(
    request: Request,
    payload: DNSIntelligenceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Runs name server/TXT/MX lookup (Milestone 4), Certificate
    Transparency subdomain enumeration, DMARC lookup, SPF analysis, and
    SecurityTrails historical DNS (Milestone 9 Part 5, optional)
    concurrently against a domain.
    """

    service = DNSIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            domain=payload.domain,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="DNS intelligence investigation failed",
        )

    return investigation


# ==========================================================
# Fetch a DNS Intelligence Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_dns_intelligence_investigation(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    repository = InvestigationRepository(db)

    investigation = repository.get_owned(
        investigation_id,
        current_user.id,
    )

    if investigation is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    return investigation
