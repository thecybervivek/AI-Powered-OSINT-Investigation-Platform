import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.email.disposable_integration import DisposableEmailIntegration
from backend.app.integrations.email.emailrep_integration import EmailRepIntegration
from backend.app.integrations.email.gravatar_integration import GravatarIntegration
from backend.app.integrations.email.hibp_integration import HIBPIntegration
from backend.app.integrations.email.mx_integration import MXLookupIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

_ENGINES = [
    EmailRepIntegration(),
    HIBPIntegration(),
    GravatarIntegration(),
    MXLookupIntegration(),
    DisposableEmailIntegration(),
]


class EmailIntelligenceService:
    """
    Orchestrates Milestone 3 (Email Intelligence): reputation (EmailRep),
    breach history (HIBP), Gravatar profile presence, MX/domain
    validity, and disposable-address detection — run concurrently and
    persisted as one Investigation with per-source InvestigationResults.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        email: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.EMAIL,
                target=email,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        engine_results: list[IntegrationResult] = await asyncio.gather(
            *(engine.run(email) for engine in _ENGINES)
        )

        results_by_source = {r.source: r for r in engine_results}

        for engine_result in engine_results:

            self.repository.add_result(
                InvestigationResult(
                    investigation_id=investigation.id,
                    source=engine_result.source,
                    status=engine_result.status,
                    data=engine_result.data,
                    latency_ms=engine_result.latency_ms,
                    error_message=engine_result.error_message,
                )
            )

        risk_score, risk_notes = self._compute_risk_score(results_by_source)

        overall_status = self._overall_status(engine_results)

        summary = self._build_summary(email, results_by_source, risk_notes)

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    def _overall_status(
        self,
        engine_results: list[IntegrationResult],
    ) -> InvestigationStatus:

        actionable = [
            r for r in engine_results if r.status != ModuleResultStatus.SKIPPED
        ]

        if not actionable:
            return InvestigationStatus.FAILED

        if all(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.FAILED

        if any(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.PARTIAL

        return InvestigationStatus.COMPLETED

    def _compute_risk_score(
        self,
        results: dict[str, IntegrationResult],
    ) -> tuple[float, list[str]]:
        """
        Builds a 0-100 exposure/risk score from breach history, reputation
        flags, and disposable-address status. Every contributing signal is
        recorded in `notes` so the summary stays explainable.
        """

        score = 0.0
        notes: list[str] = []

        hibp = results.get("hibp")

        if hibp and hibp.status == ModuleResultStatus.SUCCESS and hibp.data:

            breach_count = hibp.data.get("breach_count", 0)

            if breach_count:
                score += clamp(breach_count * 8, high=45)
                notes.append(f"{breach_count} known data breach(es)")

            if hibp.data.get("contains_sensitive_breach"):
                score += 15
                notes.append("involved in a sensitive breach")

        emailrep = results.get("emailrep")

        if emailrep and emailrep.status == ModuleResultStatus.SUCCESS and emailrep.data:

            if emailrep.data.get("suspicious"):
                score += 15
                notes.append("flagged suspicious by EmailRep")

            if emailrep.data.get("malicious_activity"):
                score += 20
                notes.append("associated with malicious activity")

            if emailrep.data.get("credentials_leaked"):
                score += 10
                notes.append("credentials leaked")

            if emailrep.data.get("new_domain"):
                score += 5
                notes.append("mail domain recently registered")

        disposable = results.get("disposable_email")

        if disposable and disposable.status == ModuleResultStatus.SUCCESS and disposable.data:

            if disposable.data.get("is_disposable"):
                score += 10
                notes.append("disposable email provider")

        mx = results.get("mx_lookup")

        if mx and mx.status == ModuleResultStatus.NOT_FOUND:
            score += 10
            notes.append("domain does not accept mail (no MX records)")

        return clamp(score), notes

    def _build_summary(
        self,
        email: str,
        results: dict[str, IntegrationResult],
        risk_notes: list[str],
    ) -> str:

        if not risk_notes:
            return f"No notable risk signals found for '{email}'."

        return f"Risk signals for '{email}': " + "; ".join(risk_notes) + "."
