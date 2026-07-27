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
from backend.app.schemas.composite_risk import CompositeRiskRequest
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.services.composite_risk_service import CompositeRiskService

router = APIRouter()


# ==========================================================
# Run Composite Risk Assessment
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
def combine_risk_assessment(
    request: Request,
    payload: CompositeRiskRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Combines the already-computed risk scores of several of your own
    past investigations (any type - username, email, domain, IP, URL,
    file, phone, threat intelligence, malware, etc.) into one composite
    risk score/level, a confidence score reflecting how corroborated
    and complete the underlying evidence is, and cross-investigation
    evidence correlation (shared indicators across investigations).
    Runs no new external lookups - purely combines existing results.
    """

    service = CompositeRiskService(db)

    try:
        investigation = service.combine(
            user_id=current_user.id,
            investigation_ids=payload.investigation_ids,
            label=payload.label,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Composite risk assessment failed",
        )

    return investigation


# ==========================================================
# Fetch a Composite Risk Assessment by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_composite_risk_assessment(
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
