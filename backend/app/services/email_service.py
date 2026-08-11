import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.email.disposable_integration import DisposableEmailIntegration
from backend.app.integrations.email.emailrep_integration import EmailRepIntegration
from backend.app.integrations.email.ghunt_integration import GHuntIntegration
from backend.app.integrations.email.gravatar_integration import GravatarIntegration
from backend.app.integrations.email.hibp_integration import HIBPIntegration
from backend.app.integrations.email.holehe_integration import HoleheIntegration
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
    HoleheIntegration(),
    GHuntIntegration(),
]

# Sources whose findings represent account-existence discovery rather
# than a security/reputation signal. Kept as a set (not a hardcoded
# single name) so a second account-presence provider can be added
# later and automatically participate in dedup + get excluded from
# risk scoring the same way, without touching either of those methods.
_ACCOUNT_PRESENCE_SOURCES = {"holehe"}


class EmailIntelligenceService:
    """
    Orchestrates Milestone 3 (Email Intelligence): reputation (EmailRep),
    breach history (HIBP), Gravatar profile presence, MX/domain
    validity, disposable-address detection, holehe-style account-
    presence checking, and an optional (disabled-by-default) Google
    intelligence slot — run concurrently and persisted as one
    Investigation with per-source InvestigationResults.
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

        account_presence = self._merge_account_presence(results_by_source)

        risk_score, risk_notes = self._compute_risk_score(results_by_source)

        overall_status = self._overall_status(engine_results)

        summary = self._build_summary(
            email, results_by_source, risk_notes, account_presence,
        )

        # Persisted, structured explanation rows — mirrors the Domain/
        # URL modules' `threat_assessment` result row, so the frontend
        # renders "why" from real stored data instead of re-parsing the
        # prose summary string. Additive: old investigations without
        # these two rows still render fine (frontend treats them as
        # optional), and neither is scored or read by
        # _compute_risk_score, so they can't create a feedback loop.
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

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="account_presence_summary",
                status=ModuleResultStatus.SUCCESS,
                data={"platforms": account_presence},
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

        # Deliberately NOT scored: holehe (_ACCOUNT_PRESENCE_SOURCES) and
        # google_intelligence. Finding an account on a platform is
        # discoverability, not a risk signal on its own — see the
        # module docstring / PR notes for why this differs from the
        # Username module's count-based exposure score. A provider
        # being SKIPPED (e.g. google_intelligence with no session
        # configured) or RATE_LIMITED never subtracts or adds here
        # either — only conclusive SUCCESS data above contributes.

        return clamp(score), notes

    def _merge_account_presence(
        self,
        results: dict[str, IntegrationResult],
    ) -> list[dict]:
        """
        Deduplicated account-presence view across every source in
        _ACCOUNT_PRESENCE_SOURCES (currently just holehe). If a second
        such provider is ever added, a platform confirmed by either one
        collapses into a single entry here instead of appearing twice,
        while `sources` keeps every provider that reported on it.
        """

        by_platform: dict[str, dict] = {}

        for source_name in _ACCOUNT_PRESENCE_SOURCES:

            engine_result = results.get(source_name)

            if not engine_result or engine_result.status == ModuleResultStatus.SKIPPED:
                continue

            for row in (engine_result.data or {}).get("results", []):

                platform = row["platform"]
                entry = by_platform.setdefault(
                    platform,
                    {
                        "platform": platform,
                        "domain": row.get("domain"),
                        "category": row.get("category"),
                        "status": row.get("status"),
                        "confidence": row.get("confidence"),
                        "evidence": row.get("evidence"),
                        "checked_at": row.get("checked_at"),
                        "provider_reason": row.get("provider_reason"),
                        "profile_url": row.get("profile_url"),
                        "sources": [],
                    },
                )

                entry["sources"].append(source_name)

                # CONFIRMED from any source wins over a NOT_FOUND/
                # UNKNOWN already recorded for the same platform; its
                # confidence/evidence/reason travel with it so the
                # merged entry stays internally consistent rather than
                # mixing a "confirmed" status with a stale UNKNOWN's
                # explanation.
                if row.get("status") == "confirmed" and entry["status"] != "confirmed":
                    entry["status"] = "confirmed"
                    entry["confidence"] = row.get("confidence")
                    entry["evidence"] = row.get("evidence")
                    entry["provider_reason"] = row.get("provider_reason")

                if not entry["profile_url"] and row.get("profile_url"):
                    entry["profile_url"] = row["profile_url"]

        return list(by_platform.values())

    def _build_summary(
        self,
        email: str,
        results: dict[str, IntegrationResult],
        risk_notes: list[str],
        account_presence: list[dict],
    ) -> str:
        """
        Distinguishes 4 cases so the summary never conflates "checked
        and clean" with "couldn't check":

          A. No breach evidence, no confirmed accounts -> plain "clean"
          B. Confirmed accounts but no risk-relevant evidence -> accounts
             are noted, explicitly NOT framed as risk
          C. Breach evidence contributed to the score -> led with that
          D. A risk-relevant provider (HIBP/EmailRep) didn't produce a
             conclusive result (SKIPPED/FAILED/RATE_LIMITED) and no
             positive risk evidence was found elsewhere -> "unavailable",
             never phrased as "no breach found"
        """

        confirmed_accounts = [
            p for p in account_presence if p["status"] == "confirmed"
        ]
        breach_notes = [n for n in risk_notes if "breach" in n]

        inconclusive_sources = [
            results.get(name) for name in ("hibp", "emailrep")
        ]
        has_unavailable_risk_source = any(
            r is not None and r.status in (
                ModuleResultStatus.SKIPPED,
                ModuleResultStatus.FAILED,
                ModuleResultStatus.RATE_LIMITED,
            )
            for r in inconclusive_sources
        )

        if breach_notes:
            message = (
                f"Confirmed breach exposure was identified for '{email}' and "
                "contributed to the risk assessment."
            )
        elif has_unavailable_risk_source and not risk_notes:
            message = (
                f"Some intelligence sources were unavailable for '{email}', so "
                "no definitive conclusion can be made."
            )
        elif confirmed_accounts and not risk_notes:
            message = (
                f"Public account associations were identified for '{email}', "
                "but no confirmed security risk signals contributed to the "
                "risk score."
            )
        elif risk_notes:
            message = f"Risk signals for '{email}': " + "; ".join(risk_notes) + "."
        else:
            message = f"No notable risk signals found for '{email}'."

        if confirmed_accounts and breach_notes:
            platform_names = ", ".join(p["platform"] for p in confirmed_accounts)
            message += f" Registered account(s) also detected on: {platform_names}."

        return message
