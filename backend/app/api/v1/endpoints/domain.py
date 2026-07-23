import ipaddress

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from sqlalchemy.orm import Session

from backend.app.core.dependencies import get_current_user
from backend.app.db.database import get_db
from backend.app.models.investigation import InvestigationType
from backend.app.models.user import User
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.schemas.domain import DomainInvestigationRequest
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.services.domain_service import DomainIntelligenceService

router = APIRouter()


def _infer_investigation_type(target: str) -> InvestigationType:

    try:
        ipaddress.ip_address(target)
        return InvestigationType.IP_ADDRESS

    except ValueError:
        return InvestigationType.DOMAIN


# ==========================================================
# Run Domain / IP / DNS Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def investigate_domain(
    payload: DomainInvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Runs WHOIS, DNS record enumeration, reverse DNS, IP geolocation,
    ASN lookup, SSL certificate inspection, and lightweight technology
    detection concurrently against a domain or IP target, and persists
    a unified investigation record.
    """

    service = DomainIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            target=payload.target,
            investigation_type=_infer_investigation_type(payload.target),
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Domain investigation failed: {error}",
        )

    return investigation


# ==========================================================
# Fetch a Domain / IP / DNS Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_domain_investigation(
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
