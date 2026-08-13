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
from backend.app.schemas.phone import PhoneInvestigationRequest
from backend.app.services.phone_service import PhoneIntelligenceService

router = APIRouter()


# ==========================================================
# Run Phone Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def investigate_phone(
    request: Request,
    payload: PhoneInvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Runs Phone Intelligence 2.0: offline libphonenumber validation/
    normalization (structural validity, E.164 formatting, region,
    number type, timezones), optionally cross-verified against
    NumVerify's live carrier/line-type database, plus Reputation,
    Breach, and Public Intelligence layers where configured. Persists a
    unified investigation record with an evidence-driven risk score -
    validity, carrier, and country facts never contribute to risk on
    their own; only confirmed reputation/breach findings do.
    """

    service = PhoneIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            phone_number=payload.phone_number,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Phone investigation failed",
        )

    return investigation


# ==========================================================
# Fetch a Phone Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_phone_investigation(
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
