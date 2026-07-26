from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from backend.app.models.investigation import RiskLevel
from backend.app.models.report import AIEngineUsed
from backend.app.models.report import ReportStatus


class ReportGenerateRequest(BaseModel):

    investigation_ids: list[str] = Field(
        min_length=1,
        max_length=50,
        description="One or more investigation IDs owned by the caller to correlate into a single report.",
    )

    title: str | None = Field(
        default=None,
        max_length=500,
        description="Optional custom title; a descriptive one is generated automatically if omitted.",
    )


class ReportResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str
    title: str
    investigation_ids: list[str]
    status: ReportStatus

    executive_summary: str | None = None
    technical_summary: str | None = None
    investigation_summary: str | None = None
    threat_analysis: str | None = None
    risk_explanation: str | None = None

    risk_score: float | None = None
    risk_level: RiskLevel | None = None

    indicators_of_compromise: list | None = None
    evidence_timeline: list | None = None
    evidence_correlation: list | None = None
    ai_recommendations: list | None = None
    mitre_attack_mapping: list | None = None
    investigation_metadata: dict | None = None

    ai_engine_used: AIEngineUsed | None = None
    confidence_score: float | None = None

    error_message: str | None = None

    created_at: datetime
    updated_at: datetime


class ReportSummary(BaseModel):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str
    title: str
    status: ReportStatus
    risk_score: float | None = None
    risk_level: RiskLevel | None = None
    ai_engine_used: AIEngineUsed | None = None
    created_at: datetime
