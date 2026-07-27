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
from backend.app.schemas.breach import BreachInvestigationRequest
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.services.breach_service import BreachIntelligenceService

router = APIRouter()


# ==========================================================
# Run Breach Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def investigate_breach(
    request: Request,
    payload: BreachInvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    For an email target: checks HaveIBeenPwned + DeHashed (optional) +
    EmailRep concurrently, and builds a breach timeline, exposed-email
    list, and password exposure status. For a domain target: runs
    DeHashed's domain-wide search only (HIBP's public tier and EmailRep
    are both per-email). Gracefully degrades when DeHashed isn't
    configured - EmailRep's own breach signal still provides a local
    fallback for email targets.
    """

    service = BreachIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            target=payload.target,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Breach investigation failed",
        )

    return investigation


# ==========================================================
# Fetch a Breach Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_breach_investigation(
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
