from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from sqlalchemy.orm import Session

from backend.app.core.dependencies import get_current_user
from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.schemas.username import UsernameInvestigationRequest
from backend.app.services.username_service import UsernameIntelligenceService

router = APIRouter()


# ==========================================================
# Run Username Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def investigate_username(
    payload: UsernameInvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Runs Sherlock, Maigret, and WhatsMyName-style checks concurrently
    against the target username and persists a unified investigation
    record with per-platform results.
    """

    service = UsernameIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            username=payload.username,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Username investigation failed",
        )

    return investigation


# ==========================================================
# Fetch a Username Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_username_investigation(
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
