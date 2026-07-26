import uuid
from enum import Enum

from sqlalchemy import JSON
from sqlalchemy import Enum as SqlEnum
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from backend.app.models.base import BaseModel
from backend.app.models.base import TimestampMixin
from backend.app.models.investigation import RiskLevel


class ReportStatus(str, Enum):

    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class AIEngineUsed(str, Enum):

    OPENAI = "openai"
    LOCAL_DETERMINISTIC = "local_deterministic"


class Report(
    BaseModel,
    TimestampMixin,
):
    """
    A generated investigation report, correlating one or more
    Investigations into a single analyst-facing document: executive
    summary, technical detail, IOCs, evidence timeline, MITRE ATT&CK
    mapping, and AI-generated recommendations.

    Content is stored structured (JSON/Text columns) rather than as a
    rendered file - JSON/Markdown/PDF exports (Part 3) are all derived
    from this same stored content on demand, so there is exactly one
    source of truth per report regardless of which format a caller asks
    for.
    """

    __tablename__ = "reports"

    __table_args__ = (
        Index(
            "ix_reports_user_created",
            "user_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    investigation_ids: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )

    status: Mapped[ReportStatus] = mapped_column(
        SqlEnum(ReportStatus),
        default=ReportStatus.GENERATING,
        nullable=False,
        index=True,
    )

    # --- Report content (Part 1 required sections) ------------------

    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    technical_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    investigation_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)

    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[RiskLevel | None] = mapped_column(
        SqlEnum(RiskLevel),
        nullable=True,
    )

    indicators_of_compromise: Mapped[list | None] = mapped_column(JSON, nullable=True)
    evidence_timeline: Mapped[list | None] = mapped_column(JSON, nullable=True)
    evidence_correlation: Mapped[list | None] = mapped_column(JSON, nullable=True)
    ai_recommendations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    mitre_attack_mapping: Mapped[list | None] = mapped_column(JSON, nullable=True)
    investigation_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # --- AI engine provenance -----------------------------------------

    ai_engine_used: Mapped[AIEngineUsed | None] = mapped_column(
        SqlEnum(AIEngineUsed),
        nullable=True,
    )
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:

        return (
            f"<Report(id={self.id}, title='{self.title}', "
            f"status={self.status})>"
        )
