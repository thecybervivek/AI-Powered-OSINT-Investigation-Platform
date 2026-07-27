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
from backend.app.schemas.social_media import SocialMediaInvestigationRequest
from backend.app.services.social_media_service import SocialMediaIntelligenceService

router = APIRouter()


# ==========================================================
# Run Social Media Investigation
# ==========================================================

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def investigate_social_media(
    request: Request,
    payload: SocialMediaInvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Checks public profile existence for the primary username across
    GitHub, LinkedIn, X (Twitter), Instagram, Facebook, Reddit, Medium,
    and HackerOne, and - if related_usernames are supplied - correlates
    which of those alias candidates share platforms with the primary
    handle. Only public profile-existence checks are performed; nothing
    behind a login wall is accessed, and no platform is scraped beyond
    what its own public pages already expose.
    """

    service = SocialMediaIntelligenceService(db)

    try:
        investigation = await service.investigate(
            user_id=current_user.id,
            username=payload.username,
            related_usernames=payload.related_usernames,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Social media investigation failed",
        )

    return investigation


# ==========================================================
# Fetch a Social Media Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_social_media_investigation(
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
