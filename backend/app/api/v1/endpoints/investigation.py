from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query
from fastapi import status

from sqlalchemy.orm import Session

from backend.app.core.dependencies import get_current_user
from backend.app.db.database import get_db
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.user import User
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.schemas.investigation import InvestigationResponse
from backend.app.schemas.investigation import InvestigationSummary
from backend.app.schemas.investigation import PaginatedResponse
from backend.app.utils.pagination import PageParams
from backend.app.utils.pagination import build_paginated_meta
from backend.app.utils.pagination import page_params

router = APIRouter()


# ==========================================================
# List Investigations (all types, paginated + filtered + searchable)
# ==========================================================

@router.get(
    "",
    response_model=PaginatedResponse[InvestigationSummary],
)
def list_investigations(
    investigation_type: InvestigationType | None = Query(default=None, alias="type"),
    status_filter: InvestigationStatus | None = Query(default=None, alias="status"),
    query: str | None = Query(default=None, description="Search by target."),
    page_params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    repository = InvestigationRepository(db)

    investigations, total = repository.search(
        user_id=current_user.id,
        investigation_type=investigation_type,
        status=status_filter,
        query=query,
        offset=page_params.offset,
        limit=page_params.limit,
    )

    return PaginatedResponse(
        items=[InvestigationSummary.model_validate(i) for i in investigations],
        **build_paginated_meta(
            total=total,
            page=page_params.page,
            page_size=page_params.page_size,
        ),
    )


# ==========================================================
# Get an Investigation (any type) by ID
# ==========================================================

@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
)
def get_investigation(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    repository = InvestigationRepository(db)
    investigation = repository.get_owned(investigation_id, current_user.id)

    if investigation is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    return investigation


# ==========================================================
# Delete an Investigation (any type)
# ==========================================================

@router.delete(
    "/{investigation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_investigation(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    repository = InvestigationRepository(db)
    investigation = repository.get_owned(investigation_id, current_user.id)

    if investigation is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    repository.delete(investigation)

    return None
