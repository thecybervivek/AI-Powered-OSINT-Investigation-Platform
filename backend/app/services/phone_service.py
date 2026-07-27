import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.phone.numverify_integration import NumVerifyIntegration
from backend.app.integrations.phone.phone_validation_integration import PhoneValidationIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

_ENGINES = [
    PhoneValidationIntegration(),
    NumVerifyIntegration(),
]

# Line types associated with disposable/anonymous-friendly numbers
# (VOIP services, virtual/burner-number providers) are a well-established
# fraud-risk signal in phone-verification systems generally - not a
# judgment about any individual, just about how easily the number could
# be replaced/discarded.
_HIGHER_RISK_NUMBER_TYPES = {"voip", "premium_rate", "pager", "personal_number"}


class PhoneIntelligenceService:
    """
    Orchestrates Milestone 9 Part 1 (Phone Intelligence): offline
    structural validation/formatting/carrier/region/timezone lookup via
    libphonenumber, optionally cross-verified against NumVerify's live
    carrier/line-type database, merged into one risk-scored
    Investigation record.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        phone_number: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.PHONE,
                target=phone_number,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        engine_results: list[IntegrationResult] = await asyncio.gather(
            *(engine.run(phone_number) for engine in _ENGINES)
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
        summary = self._build_summary(phone_number, results_by_source, risk_notes)

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

        score = 0.0
        notes: list[str] = []

        validation = results.get("phone_validation")

        if validation and validation.data:

            if not validation.data.get("is_valid", False):
                score += 40
                notes.append("number does not validate as a real, assignable number")

            number_type = validation.data.get("number_type")

            if number_type in _HIGHER_RISK_NUMBER_TYPES:
                score += 20
                notes.append(f"number type is '{number_type}'")

        numverify = results.get("numverify")

        if numverify and numverify.status == ModuleResultStatus.SUCCESS and numverify.data:

            line_type = (numverify.data.get("line_type") or "").lower()

            if line_type == "voip":
                score += 20
                notes.append("NumVerify confirms a VOIP line")

        return clamp(score), notes

    def _build_summary(
        self,
        phone_number: str,
        results: dict[str, IntegrationResult],
        risk_notes: list[str],
    ) -> str:

        validation = results.get("phone_validation")

        if validation and validation.data and not validation.data.get("is_valid", False):
            return f"'{phone_number}' does not validate as a real phone number."

        if not risk_notes:
            return f"No notable risk signals found for '{phone_number}'."

        return f"Risk signals for '{phone_number}': " + "; ".join(risk_notes) + "."
