from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi import Response
from fastapi import status

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import get_current_user
from backend.app.core.rate_limit import limiter
from backend.app.db.database import get_db
from backend.app.models.report import ReportStatus
from backend.app.models.user import User
from backend.app.repositories.report_repository import ReportRepository
from backend.app.schemas.investigation import PaginatedResponse
from backend.app.schemas.report import ReportGenerateRequest
from backend.app.schemas.report import ReportResponse
from backend.app.schemas.report import ReportSummary
from backend.app.services.report_export import export_json
from backend.app.services.report_export import export_markdown
from backend.app.services.report_export import export_pdf
from backend.app.services.report_service import InvestigationNotFoundError
from backend.app.services.report_service import ReportService
from backend.app.utils.pagination import PageParams
from backend.app.utils.pagination import build_paginated_meta
from backend.app.utils.pagination import page_params

router = APIRouter()


# ==========================================================
# Generate a Report
# ==========================================================

@router.post(
    "/generate",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.RATE_LIMIT_INVESTIGATION)
async def generate_report(
    request: Request,
    body: ReportGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Correlates one or more of the caller's own investigations into a
    single AI-analyzed report: executive/technical summaries, IOCs,
    evidence timeline, MITRE ATT&CK mapping, and recommendations.
    """

    service = ReportService(db)

    try:
        report = await service.generate(
            user_id=current_user.id,
            investigation_ids=body.investigation_ids,
            title=body.title,
        )

    except InvestigationNotFoundError as error:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "One or more investigations were not found or are not "
                f"owned by the caller: {error.missing_ids}"
            ),
        )

    return report


# ==========================================================
# List Reports (paginated + filtered)
# ==========================================================

@router.get(
    "",
    response_model=PaginatedResponse[ReportSummary],
)
def list_reports(
    status_filter: ReportStatus | None = Query(default=None, alias="status"),
    query: str | None = Query(default=None, description="Search by report title."),
    page_params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    repository = ReportRepository(db)

    reports, total = repository.search(
        user_id=current_user.id,
        status=status_filter,
        query=query,
        offset=page_params.offset,
        limit=page_params.limit,
    )

    return PaginatedResponse(
        items=[ReportSummary.model_validate(r) for r in reports],
        **build_paginated_meta(
            total=total,
            page=page_params.page,
            page_size=page_params.page_size,
        ),
    )


# ==========================================================
# Get a Report (JSON by default; ?format=markdown|pdf for export)
# ==========================================================

@router.get(
    "/{report_id}",
)
def get_report(
    report_id: str,
    export_format: str = Query(
        default="json",
        alias="format",
        pattern="^(json|markdown|pdf)$",
        description="Response format: json (default), markdown, or pdf.",
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    repository = ReportRepository(db)
    report = repository.get_owned(report_id, current_user.id)

    if report is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )

    if export_format == "markdown":

        return Response(
            content=export_markdown(report),
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="report-{report.id}.md"',
            },
        )

    if export_format == "pdf":

        return Response(
            content=export_pdf(report),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report-{report.id}.pdf"',
            },
        )

    return Response(
        content=export_json(report),
        media_type="application/json",
    )


# ==========================================================
# Delete a Report
# ==========================================================

@router.delete(
    "/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    repository = ReportRepository(db)
    deleted = repository.delete_owned(report_id, current_user.id)

    if not deleted:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )

    return None
