import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.username import MaigretIntegration
from backend.app.integrations.username import SherlockIntegration
from backend.app.integrations.username import WhatsMyNameIntegration
from backend.app.integrations.username.normalization import normalize_and_correlate
from backend.app.integrations.username.normalization import summarize_findings
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository

_ENGINES = [
    SherlockIntegration(),
    MaigretIntegration(),
    WhatsMyNameIntegration(),
]


class UsernameIntelligenceService:
    """
    Orchestrates Milestone 2 (Username Intelligence): runs every engine
    concurrently against the target username, normalizes and
    deduplicates their raw per-platform results into one canonical,
    cross-engine view (see integrations/username/normalization.py),
    and persists everything into the Investigation tables.

    Username Intelligence is public profile-discovery, not threat
    scoring: how many platforms a handle turns up on says nothing
    about whether the person is a security risk. This service
    therefore NEVER computes a risk_score/risk_level - both are left
    None (the Investigation model already supports this), the same
    neutral behavior any other module falls back to when it has no
    risk verdict to report.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        username: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.USERNAME,
                target=username,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        engine_results: list[IntegrationResult] = await asyncio.gather(
            *(engine.run(username) for engine in _ENGINES)
        )

        # Persist each engine's raw result for auditing - untouched,
        # exactly as returned, regardless of what normalization later
        # does with it.
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

        findings = normalize_and_correlate(engine_results)
        summary_data = summarize_findings(findings)

        engines_run = [
            r.source for r in engine_results
            if r.status != ModuleResultStatus.SKIPPED
        ]

        normalization_result = IntegrationResult(
            source="username_normalization",
            status=ModuleResultStatus.SUCCESS,
            data={
                "username": username,
                "engines_run": engines_run,
                **summary_data,
            },
        )

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source=normalization_result.source,
                status=normalization_result.status,
                data=normalization_result.data,
            )
        )

        overall_status = self._overall_status(engine_results)

        summary = self._build_summary(username, summary_data)

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=None,
            risk_level=None,
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------
    # Summary text - describes findings, not threat risk.
    # ------------------------------------------------------

    def _build_summary(self, username: str, summary_data: dict) -> str:

        confirmed = len(summary_data["confirmed_profiles"])
        not_found = len(summary_data["not_found_platforms"])
        unknown = len(summary_data["unable_to_verify_platforms"])
        providers = summary_data["providers_consulted"]

        if not providers:
            return (
                f"Username investigation for '{username}' could not be "
                f"completed - no engine returned usable results."
            )

        return (
            f"Username '{username}': {confirmed} confirmed profile"
            f"{'' if confirmed == 1 else 's'}, {not_found} platform"
            f"{'' if not_found == 1 else 's'} confidently checked and "
            f"not found, {unknown} unable to verify, across "
            f"{len(providers)} engine{'' if len(providers) == 1 else 's'} "
            f"({', '.join(providers)})."
        )

    def _overall_status(
        self,
        engine_results: list[IntegrationResult],
    ) -> InvestigationStatus:

        statuses = [r.status for r in engine_results]

        if all(s == ModuleResultStatus.FAILED for s in statuses):
            return InvestigationStatus.FAILED

        if any(s == ModuleResultStatus.FAILED for s in statuses):
            return InvestigationStatus.PARTIAL

        return InvestigationStatus.COMPLETED
