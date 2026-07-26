from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import RiskLevel
from backend.app.models.report import Report
from backend.app.models.report import ReportStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.repositories.report_repository import ReportRepository
from backend.app.services.ai_analysis_engine import AIAnalysisEngine
from backend.app.services.ai_analysis_engine import flatten_evidence
from backend.app.services.mitre_mapping import map_mitre_attack

_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class InvestigationNotFoundError(Exception):
    """Raised when one or more requested investigation_ids don't exist
    or aren't owned by the requesting user."""

    def __init__(self, missing_ids: list[str]) -> None:
        self.missing_ids = missing_ids
        super().__init__(
            f"Investigation(s) not found or not owned by caller: {missing_ids}"
        )


class ReportService:
    """
    Orchestrates Milestone 7: fetches every requested Investigation
    (ownership-checked), correlates them through the AI Analysis Engine
    and the deterministic MITRE ATT&CK mapper, and persists the result
    as a single Report. Never partially writes a Report - either every
    requested investigation is found and the report completes, or the
    whole call raises before any Report row is created.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.investigations = InvestigationRepository(db)
        self.reports = ReportRepository(db)
        self.ai_engine = AIAnalysisEngine()

    async def generate(
        self,
        *,
        user_id: str,
        investigation_ids: list[str],
        title: str | None,
    ) -> Report:

        investigations, missing_ids = self._fetch_owned(
            investigation_ids=investigation_ids,
            user_id=user_id,
        )

        if missing_ids:
            raise InvestigationNotFoundError(missing_ids)

        report = self.reports.create(
            Report(
                user_id=user_id,
                title=title or self._default_title(investigations),
                investigation_ids=investigation_ids,
                status=ReportStatus.GENERATING,
            )
        )

        try:
            analysis = await self.ai_engine.analyze(investigations)
        except Exception as error:  # pragma: no cover - AIAnalysisEngine
            # already falls back internally; this is a final safety net
            # so a Report row is never left stuck in GENERATING.
            return self.reports.update(
                report,
                status=ReportStatus.FAILED,
                error_message=f"AI analysis failed unexpectedly: {error}",
            )

        evidence_items = flatten_evidence(investigations)
        mitre_mapping = map_mitre_attack(evidence_items)

        risk_score, risk_level = self._aggregate_risk(investigations)

        return self.reports.update(
            report,
            status=ReportStatus.COMPLETED,
            executive_summary=analysis.executive_summary,
            technical_summary=analysis.technical_analysis,
            investigation_summary=self._build_investigation_summary(investigations),
            threat_analysis=analysis.threat_summary,
            risk_explanation=analysis.risk_explanation,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators_of_compromise=self._build_iocs(investigations),
            evidence_timeline=self._build_timeline(investigations),
            evidence_correlation=analysis.evidence_correlation,
            ai_recommendations=analysis.recommendations,
            mitre_attack_mapping=mitre_mapping,
            investigation_metadata=self._build_metadata(investigations),
            ai_engine_used=analysis.engine_used,
            confidence_score=analysis.confidence_score,
        )

    # ==========================================================
    # Fetch + validation
    # ==========================================================

    def _fetch_owned(
        self,
        *,
        investigation_ids: list[str],
        user_id: str,
    ) -> tuple[list[Investigation], list[str]]:

        investigations: list[Investigation] = []
        missing_ids: list[str] = []

        for investigation_id in investigation_ids:

            investigation = self.investigations.get_owned(investigation_id, user_id)

            if investigation is None:
                missing_ids.append(investigation_id)
            else:
                investigations.append(investigation)

        return investigations, missing_ids

    # ==========================================================
    # Report content builders
    # ==========================================================

    @staticmethod
    def _default_title(investigations: list[Investigation]) -> str:

        targets = ", ".join(inv.target for inv in investigations[:3])

        if len(investigations) > 3:
            targets += f", +{len(investigations) - 3} more"

        return f"Investigation Report - {targets}"

    @staticmethod
    def _build_investigation_summary(investigations: list[Investigation]) -> str:

        lines = [
            f"- [{inv.investigation_type.value}] '{inv.target}' - "
            f"status={inv.status.value}"
            + (
                f", risk={inv.risk_level.value} ({inv.risk_score:.1f}/100)"
                if inv.risk_level
                else ""
            )
            for inv in investigations
        ]

        return "\n".join(lines)

    @staticmethod
    def _aggregate_risk(
        investigations: list[Investigation],
    ) -> tuple[float, RiskLevel]:
        """
        The report's overall risk is driven by its single riskiest
        investigation (a report is only as safe as its worst finding),
        not an average that could dilute one CRITICAL result among many
        LOW ones.
        """

        scored = [inv for inv in investigations if inv.risk_score is not None]

        if not scored:
            return 0.0, RiskLevel.LOW

        worst = max(scored, key=lambda i: i.risk_score)

        return worst.risk_score, worst.risk_level or RiskLevel.LOW

    @staticmethod
    def _build_iocs(investigations: list[Investigation]) -> list[dict]:

        return [
            {
                "type": inv.investigation_type.value,
                "value": inv.target,
                "risk_level": inv.risk_level.value if inv.risk_level else None,
                "risk_score": inv.risk_score,
                "investigation_id": inv.id,
            }
            for inv in investigations
        ]

    @staticmethod
    def _build_timeline(investigations: list[Investigation]) -> list[dict]:

        events: list[dict] = []

        for inv in investigations:

            if inv.started_at:
                events.append(
                    {
                        "timestamp": inv.started_at.isoformat(),
                        "event": (
                            f"Investigation started: {inv.investigation_type.value} "
                            f"'{inv.target}'"
                        ),
                        "investigation_id": inv.id,
                    }
                )

            if inv.completed_at:
                events.append(
                    {
                        "timestamp": inv.completed_at.isoformat(),
                        "event": (
                            f"Investigation completed: status={inv.status.value}"
                        ),
                        "investigation_id": inv.id,
                    }
                )

            for result in inv.results:

                if result.source == "timeline_analysis" and result.data:

                    for key, value in result.data.items():

                        if value:
                            events.append(
                                {
                                    "timestamp": value,
                                    "event": f"File {key.replace('_', ' ')}",
                                    "investigation_id": inv.id,
                                }
                            )

        events.sort(key=lambda e: e["timestamp"] or "")

        return events

    @staticmethod
    def _build_metadata(investigations: list[Investigation]) -> dict:

        type_counts: dict[str, int] = {}

        for inv in investigations:
            type_counts[inv.investigation_type.value] = (
                type_counts.get(inv.investigation_type.value, 0) + 1
            )

        return {
            "investigation_count": len(investigations),
            "investigation_types": type_counts,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": settings.APP_NAME,
            "platform_version": settings.APP_VERSION,
        }
