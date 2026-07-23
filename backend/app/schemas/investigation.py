from datetime import datetime
from typing import Generic
from typing import TypeVar

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.models.investigation import RiskLevel


# ==========================================================
# Create Investigation
# ==========================================================

class InvestigationCreate(BaseModel):

    investigation_type: InvestigationType

    target: str = Field(
        min_length=1,
        max_length=500,
    )


# ==========================================================
# Investigation Result
# ==========================================================

class InvestigationResultResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    source: str

    status: ModuleResultStatus

    data: dict | None = None

    latency_ms: int | None = None

    error_message: str | None = None

    created_at: datetime


# ==========================================================
# Investigation Response
# ==========================================================

class InvestigationResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    investigation_type: InvestigationType

    target: str

    status: InvestigationStatus

    risk_score: float | None = None

    risk_level: RiskLevel | None = None

    summary: str | None = None

    started_at: datetime | None = None

    completed_at: datetime | None = None

    error_message: str | None = None

    created_at: datetime

    updated_at: datetime

    results: list[InvestigationResultResponse] = []


# ==========================================================
# Investigation Summary (list view — no nested results)
# ==========================================================

class InvestigationSummary(BaseModel):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    investigation_type: InvestigationType

    target: str

    status: InvestigationStatus

    risk_level: RiskLevel | None = None

    created_at: datetime


# ==========================================================
# Generic Paginated Response
# ==========================================================

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):

    items: list[T]

    total: int

    page: int

    page_size: int

    total_pages: int
