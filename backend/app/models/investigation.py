import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime
from sqlalchemy import Enum as SqlEnum
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from backend.app.models.base import BaseModel
from backend.app.models.base import TimestampMixin


# ==========================================================
# Enumerations
# ==========================================================

class InvestigationType(str, Enum):
    """
    Maps 1:1 to the OSINT modules (Modules 1-9 in the spec).
    """

    USERNAME = "username"
    EMAIL = "email"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    DNS = "dns"
    URL = "url"
    PHONE = "phone"
    METADATA = "metadata"
    REVERSE_IMAGE = "reverse_image"


class InvestigationStatus(str, Enum):

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ModuleResultStatus(str, Enum):

    SUCCESS = "success"
    FAILED = "failed"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"


class RiskLevel(str, Enum):

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ==========================================================
# Investigation (parent record for a single OSINT run)
# ==========================================================

class Investigation(
    BaseModel,
    TimestampMixin,
):

    __tablename__ = "investigations"

    __table_args__ = (
        Index(
            "ix_investigations_user_created",
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

    investigation_type: Mapped[InvestigationType] = mapped_column(
        SqlEnum(InvestigationType),
        nullable=False,
        index=True,
    )

    target: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )

    status: Mapped[InvestigationStatus] = mapped_column(
        SqlEnum(InvestigationStatus),
        default=InvestigationStatus.QUEUED,
        nullable=False,
        index=True,
    )

    risk_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    risk_level: Mapped[RiskLevel | None] = mapped_column(
        SqlEnum(RiskLevel),
        nullable=True,
    )

    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    results: Mapped[list["InvestigationResult"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:

        return (
            f"<Investigation("
            f"id={self.id}, "
            f"type={self.investigation_type}, "
            f"target='{self.target}', "
            f"status={self.status})>"
        )


# ==========================================================
# InvestigationResult (one row per source/tool queried)
# ==========================================================

class InvestigationResult(
    BaseModel,
    TimestampMixin,
):

    __tablename__ = "investigation_results"

    __table_args__ = (
        Index(
            "ix_investigation_results_investigation_source",
            "investigation_id",
            "source",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    investigation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "investigations.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    status: Mapped[ModuleResultStatus] = mapped_column(
        SqlEnum(ModuleResultStatus),
        nullable=False,
    )

    data: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    raw_response: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    latency_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    investigation: Mapped["Investigation"] = relationship(
        back_populates="results",
    )

    def __repr__(self) -> str:

        return (
            f"<InvestigationResult("
            f"id={self.id}, "
            f"source='{self.source}', "
            f"status={self.status})>"
        )
