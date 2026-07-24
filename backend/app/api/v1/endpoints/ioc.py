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
from backend.app.models.investigation import InvestigationType
from backend.app.models.user import User
from backend.app.schemas.ioc import IOCAnalysisRequest
from backend.app.schemas.ioc import IOCAnalysisResponse
from backend.app.services.ioc_service import IOCAnalysisService

router = APIRouter()


# ==========================================================
# Run IOC Analysis
# ==========================================================

@router.post(
    "/analyze",
    response_model=IOCAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def analyze_ioc(
    request: Request,
    payload: IOCAnalysisRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Auto-detects whether the submitted indicator is an IP address,
    domain, URL, email address, or username, then delegates to the
    matching specialized investigation service. Use this when the
    indicator type isn't already known (e.g. triaging a raw IOC list);
    use the dedicated /investigations/{ip,url,email,domain,username}
    endpoints directly when the type is already known.
    """

    service = IOCAnalysisService(db)

    try:
        ioc_type, investigation = await service.investigate(
            user_id=current_user.id,
            indicator=payload.indicator,
        )

    except ValueError as error:

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        )

    except Exception as error:

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IOC analysis failed: {error}",
        )

    return IOCAnalysisResponse(
        detected_type=InvestigationType(ioc_type.value),
        investigation=investigation,
    )
