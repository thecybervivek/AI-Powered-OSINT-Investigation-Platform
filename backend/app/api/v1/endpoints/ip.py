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
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.schemas.ip import IPInvestigationRequest
from backend.app.services.ip_service import IPIntelligenceService

router = APIRouter()


# ==========================================================
# Run IP Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def investigate_ip(
    request: Request,
    payload: IPInvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Runs IP geolocation and ASN lookup (reused from Milestone 4)
    alongside AbuseIPDB and VirusTotal reputation checks concurrently,
    and persists a unified investigation record. Accepts either a
    literal IP address or a domain name (resolved automatically).
    """

    service = IPIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            target=payload.target,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="IP investigation failed",
        )

    return investigation


# ==========================================================
# Fetch an IP Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_ip_investigation(
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
