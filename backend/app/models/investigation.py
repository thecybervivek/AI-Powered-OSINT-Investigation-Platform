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

from backend.app.core.intelligence.db_types import StringBackedEnum
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
    FILE = "file"
    SOCIAL_MEDIA = "social_media"
    BREACH = "breach"
    THREAT_INTELLIGENCE = "threat_intelligence"
    MALWARE = "malware"
    RISK_ASSESSMENT = "risk_assessment"


class InvestigationStatus(str, Enum):

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ModuleResultStatus(str, Enum):
    """
    Provider Status Model (spec section 7). Additive: SUCCESS/FAILED/
    NOT_FOUND/RATE_LIMITED/SKIPPED already existed and keep their exact
    meaning; FOUND/PARTIAL/UNABLE_TO_VERIFY/NO_DATA are new members
    added to reach the spec's required vocabulary without repurposing
    or removing any existing one (spec: "do not invent contradictory
    states").

    SUCCESS:           provider ran and returned a usable result. For a
                        binary presence/absence check, prefer the more
                        specific FOUND/NOT_FOUND over a bare SUCCESS so
                        callers don't have to inspect `data` to know
                        which case they're in.
    FOUND:              provider ran and positively confirmed the thing
                        being checked for (e.g. a confirmed account,
                        a confirmed breach record).
    NOT_FOUND:          provider ran, produced a conclusive negative
                        result - a genuine "checked and it's not there".
    PARTIAL:            provider ran and returned a usable-but-incomplete
                        result (some sub-checks within this one provider
                        succeeded, others didn't) - distinct from the
                        Investigation-level PARTIAL in InvestigationStatus.
    UNABLE_TO_VERIFY:   provider was reached but could not reach a
                        conclusion (e.g. ambiguous/ratelimited-but-
                        partial upstream response) - NOT the same as
                        NOT_FOUND, and must never be read as a benign
                        signal.
    NO_DATA:            provider ran successfully but the upstream
                        source has no data at all for this indicator
                        (distinct from NOT_FOUND, which asserts a
                        confirmed negative; NO_DATA makes no assertion
                        either way).
    RATE_LIMITED:       provider was reached but rejected the request
                        for exceeding a rate limit - distinct from a
                        generic FAILED (see base.py's IntegrationResult
                        run() handling).
    FAILED:             provider was attempted and encountered an error
                        (timeout, non-2xx, network failure, etc).
    SKIPPED:            provider was never attempted because it isn't
                        configured/enabled.
    """

    SUCCESS = "success"
    FOUND = "found"
    NOT_FOUND = "not_found"
    PARTIAL = "partial"
    UNABLE_TO_VERIFY = "unable_to_verify"
    NO_DATA = "no_data"
    RATE_LIMITED = "rate_limited"
    FAILED = "failed"
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
        StringBackedEnum(InvestigationType, length=64),
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
        # Was SqlEnum(ModuleResultStatus) - the same native-Postgres-
        # enum footgun documented at length in investigation_registry.py
        # and already fixed once for investigation_type (see migration
        # f1a2b3c4d5e6): SqlEnum without values_callable persists the
        # member NAME ("SUCCESS"), not its .value ("success"), so this
        # column's real Postgres enum labels have only ever been the
        # uppercase names, and every one of the four new members added
        # above would need its own `ALTER TYPE ... ADD VALUE` migration
        # to become insertable. Switching to StringBackedEnum (see
        # migration a3f5c9d2b6e4_convert_module_result_status_to_string)
        # removes that class of bug the same way it was removed for
        # investigation_type - new
        # ModuleResultStatus members from here on are a one-line code
        # change with zero database migration required.
        StringBackedEnum(ModuleResultStatus, length=32),
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
