from fastapi import APIRouter
from fastapi import Depends
from fastapi import File
from fastapi import HTTPException
from fastapi import Request
from fastapi import UploadFile
from fastapi import status

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import get_current_user
from backend.app.core.rate_limit import limiter
from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.repositories.image_fingerprint_repository import ImageFingerprintRepository
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.schemas.reverse_image import ReverseImageInvestigationResponse
from backend.app.services.reverse_image_service import ReverseImageIntelligenceService

router = APIRouter()


# ==========================================================
# Upload + Investigate an Image
# ==========================================================

@router.post(
    "/upload",
    response_model=ReverseImageInvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def upload_image(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Accepts a single image upload, computes cryptographic (MD5/SHA1/
    SHA256/SHA512) and perceptual (phash/ahash/dhash) fingerprints,
    extracts EXIF/GPS metadata, and checks it against every image this
    same user has previously investigated for exact or near-duplicate
    matches - then persists everything as a Reverse Image investigation.
    """

    service = ReverseImageIntelligenceService(db)

    try:
        investigation, image_record = await service.investigate(
            user_id=current_user.id,
            upload=file,
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Reverse image investigation failed",
        )

    return ReverseImageInvestigationResponse(
        investigation=investigation,
        image=image_record,
    )


# ==========================================================
# Fetch a Reverse Image Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=ReverseImageInvestigationResponse,
)
def get_reverse_image_investigation(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    investigation_repository = InvestigationRepository(db)
    image_repository = ImageFingerprintRepository(db)

    investigation = investigation_repository.get_owned(
        investigation_id,
        current_user.id,
    )

    if investigation is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    image_record = image_repository.get_by_investigation(investigation_id)

    if image_record is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Image record not found for this investigation.",
        )

    return ReverseImageInvestigationResponse(
        investigation=investigation,
        image=image_record,
    )
