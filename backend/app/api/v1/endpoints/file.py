import logging

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
from backend.app.repositories.file_repository import FileRecordRepository
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.schemas.file import FileInvestigationResponse
from backend.app.services.file_service import FileIntelligenceService


logger = logging.getLogger("app.api.file")

router = APIRouter()


# ==========================================================
# Upload + Investigate a File
# ==========================================================

@router.post(
    "/upload",
    response_model=FileInvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Accepts a single file upload and runs the complete file-intelligence
    pipeline.

    Expected validation failures are returned as client errors.
    Unexpected failures are logged server-side with the complete
    traceback while the API returns a sanitized error response.
    """

    service = FileIntelligenceService(db)

    try:
        investigation, file_record = await service.investigate(
            user_id=current_user.id,
            upload=file,
        )

    except ValueError as error:
        logger.warning(
            "File investigation rejected for user_id=%s filename=%r: %s",
            current_user.id,
            file.filename,
            error,
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    except HTTPException:
        raise

    except Exception as error:
        logger.exception(
            "Unexpected file investigation failure for "
            "user_id=%s filename=%r",
            current_user.id,
            file.filename,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File investigation failed due to an internal server error.",
        ) from error

    return FileInvestigationResponse(
        investigation=investigation,
        file=file_record,
    )


# ==========================================================
# Fetch a File Investigation by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=FileInvestigationResponse,
)
def get_file_investigation(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    investigation_repository = InvestigationRepository(db)
    file_repository = FileRecordRepository(db)

    investigation = investigation_repository.get_owned(
        investigation_id,
        current_user.id,
    )

    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    file_record = file_repository.get_by_investigation(
        investigation_id
    )

    if file_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File record not found for this investigation.",
        )

    return FileInvestigationResponse(
        investigation=investigation,
        file=file_record,
    )