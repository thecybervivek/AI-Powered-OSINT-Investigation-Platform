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
from backend.app.schemas.threat_intelligence import ThreatIntelligenceRequest
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService

router = APIRouter()


# ==========================================================
# Run Threat Intelligence Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def investigate_threat_intelligence(
    request: Request,
    payload: ThreatIntelligenceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Runs Shodan, Censys, GreyNoise, and AlienVault OTX against the
    resolved IP, plus SecurityTrails' historical DNS against the
    original target when it's a domain - all concurrently, all
    independently optional. Providers without a configured API key
    report status=skipped rather than failing the investigation.
    """

    service = ThreatIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            target=payload.target,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Threat intelligence investigation failed",
        )

    return investigation


# ==========================================================
# Fetch a Threat Intelligence Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_threat_intelligence_investigation(
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
