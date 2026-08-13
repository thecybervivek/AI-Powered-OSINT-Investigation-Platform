import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.phone.numverify_integration import NumVerifyIntegration
from backend.app.integrations.phone.phone_breach_integration import PhoneBreachIntegration
from backend.app.integrations.phone.phone_public_intelligence_integration import (
    PhonePublicIntelligenceIntegration,
)
from backend.app.integrations.phone.phone_reputation_integration import PhoneReputationIntegration
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
    PhoneReputationIntegration(),
    PhoneBreachIntegration(),
    PhonePublicIntelligenceIntegration(),
]

# Reputation categories that count as confirmed, evidence-driven
# security signal (spec section 5/10). Any other key present in a
# reputation provider's payload (e.g. a raw confidence score) is
# reported but never scored.
_REPUTATION_RISK_FLAGS: dict[str, tuple[float, str]] = {
    "spam": (15, "reported for spam activity"),
    "scam": (25, "reported scam number"),
    "fraud": (25, "reported fraud number"),
    "abuse": (20, "reported abuse"),
    "malicious_activity": (30, "confirmed malicious activity"),
    "suspicious_activity": (10, "flagged suspicious activity"),
}


class PhoneIntelligenceService:
    """
    Orchestrates Phone Intelligence 2.0:

        Phone Overview -> Validation -> Carrier/Network -> Reputation
        -> Breach -> Public Intelligence -> Evidence -> Risk Assessment

    Architecture mirrors the mature Username Intelligence module: every
    engine runs concurrently, each raw result is persisted independently
    and auditable, and a small set of derived summary rows
    (phone_overview, risk_assessment) give the frontend a stable shape
    to render without re-parsing provider-specific payloads.

    RISK SCORING IS EVIDENCE-DRIVEN ONLY (see _compute_risk_score):
    a valid/possible number, its type, carrier, country, timezone, or
    simple discoverability NEVER contribute to risk score - the
    regression this module permanently fixes was exactly this
    (9917891298 being scored medium-risk purely because it lacked a
    "+91" prefix, which is a formatting fact, not a security finding).
    Risk only increases from confirmed reputation flags or confirmed
    breach exposure, both of which come from providers that are SKIPPED
    (not fabricated as "clean") when unconfigured.
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

        # Persist each engine's raw result untouched - independently
        # auditable, exactly as returned, regardless of what the
        # derived summary rows below do with it.
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

        overview = self._build_overview(results_by_source)

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="phone_overview",
                status=ModuleResultStatus.SUCCESS,
                data=overview,
            )
        )

        risk_score, risk_notes = self._compute_risk_score(results_by_source)
        overall_status = self._overall_status(engine_results)
        summary = self._build_summary(phone_number, results_by_source, risk_notes)

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="risk_assessment",
                status=ModuleResultStatus.SUCCESS,
                data={
                    "risk_score": risk_score,
                    "risk_level": risk_level_from_score(risk_score).value,
                    "contributing_evidence": risk_notes,
                },
            )
        )

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------
    # Phone Overview - normalization/dedup across validation + carrier
    # sources describing the same underlying number (spec section 9).
    # ------------------------------------------------------

    def _build_overview(
        self,
        results: dict[str, IntegrationResult],
    ) -> dict:

        validation = results.get("phone_validation")
        numverify = results.get("numverify")

        v_data = validation.data if validation and validation.data else {}
        n_data = (
            numverify.data
            if numverify and numverify.status == ModuleResultStatus.SUCCESS and numverify.data
            else {}
        )

        providers_agreeing: list[str] = []
        if validation and validation.data:
            providers_agreeing.append("phone_validation")
        if n_data:
            providers_agreeing.append("numverify")

        return {
            "raw_input": v_data.get("raw_input"),
            "normalized_e164": v_data.get("e164_format") or n_data.get("number"),
            "country": v_data.get("region_description") or n_data.get("country_name"),
            "country_calling_code": v_data.get("country_calling_code")
            or n_data.get("country_code"),
            "country_code": v_data.get("country_code"),
            "number_type": v_data.get("number_type"),
            "international_format": v_data.get("international_format")
            or n_data.get("international_format"),
            "national_format": v_data.get("national_format") or n_data.get("local_format"),
            "timezones": v_data.get("timezones") or [],
            "assumed_country": v_data.get("assumed_country"),
            "validation_status": (
                validation.status.value if validation else "unknown"
            ),
            "is_valid": v_data.get("is_valid"),
            "is_possible": v_data.get("is_possible"),
            "providers_consulted": providers_agreeing,
        }

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

    # ------------------------------------------------------
    # Risk scoring - evidence-driven only. See module docstring.
    # ------------------------------------------------------

    def _compute_risk_score(
        self,
        results: dict[str, IntegrationResult],
    ) -> tuple[float, list[str]]:

        score = 0.0
        notes: list[str] = []

        # --------------------------------------------------
        # Reputation Intelligence - only confirmed flags count.
        # A SKIPPED/FAILED/UNKNOWN reputation provider contributes
        # nothing (and the summary must not claim "safe" because of it
        # - see _build_summary).
        # --------------------------------------------------

        reputation = results.get("phone_reputation")

        if (
            reputation
            and reputation.status == ModuleResultStatus.SUCCESS
            and reputation.data
        ):
            for flag, (points, note) in _REPUTATION_RISK_FLAGS.items():
                if reputation.data.get(flag):
                    score += points
                    notes.append(f"reputation intelligence: {note}")

        # --------------------------------------------------
        # Breach Intelligence - only a confirmed, non-empty result
        # counts. NOT_FOUND (checked, nothing found), SKIPPED (not
        # configured), FAILED, and RATE_LIMITED all contribute nothing.
        # --------------------------------------------------

        breach = results.get("phone_breach")

        if (
            breach
            and breach.status == ModuleResultStatus.SUCCESS
            and breach.data
            and breach.data.get("total_entries", 0) > 0
        ):

            total_entries = breach.data["total_entries"]
            score += clamp(total_entries * 10, high=45)
            notes.append(
                f"confirmed breach exposure across {total_entries} record"
                f"{'' if total_entries == 1 else 's'}"
            )

            if breach.data.get("has_plaintext_password_exposure"):
                score += 15
                notes.append("plaintext password exposure in a linked breach record")

        # Deliberately NOT scored: phone_validation (validity/possibility/
        # number type), numverify (carrier/line type/country/region),
        # phone_public_intelligence (discoverability only). None of
        # these are security evidence - see spec section 10/11, and the
        # regression test suite for the exact 9917891298 case this
        # permanently fixes.

        return clamp(score), notes

    # ------------------------------------------------------
    # Summary - evidence-aware, never claims "safe" from an absence.
    # ------------------------------------------------------

    def _build_summary(
        self,
        phone_number: str,
        results: dict[str, IntegrationResult],
        risk_notes: list[str],
    ) -> str:

        validation = results.get("phone_validation")

        if validation and validation.data and not validation.data.get("is_valid", False):
            return f"'{phone_number}' does not validate as a real, assignable phone number."

        unavailable = [
            source
            for source in ("numverify", "phone_reputation", "phone_breach", "phone_public_intelligence")
            if results.get(source) is None
            or results[source].status
            in (
                ModuleResultStatus.SKIPPED,
                ModuleResultStatus.FAILED,
                ModuleResultStatus.RATE_LIMITED,
            )
        ]

        if risk_notes:
            return (
                f"Security/reputation intelligence identified findings for "
                f"'{phone_number}': " + "; ".join(risk_notes) + "."
            )

        if unavailable:
            return (
                f"Phone number '{phone_number}' was validated, but some "
                f"intelligence providers were unavailable "
                f"({', '.join(unavailable)}). No definitive security "
                f"conclusion can be made."
            )

        return (
            f"Phone number '{phone_number}' successfully validated. Carrier "
            f"and network information were collected where available. No "
            f"confirmed security or reputation evidence was found."
        )
