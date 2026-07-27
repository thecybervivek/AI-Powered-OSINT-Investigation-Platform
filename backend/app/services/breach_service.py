import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.breach.dehashed_integration import DeHashedIntegration
from backend.app.integrations.email.emailrep_integration import EmailRepIntegration
from backend.app.integrations.email.hibp_integration import HIBPIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score


class BreachIntelligenceService:
    """
    Orchestrates Milestone 9 Part 4 (Breach Intelligence).

    For an EMAIL target: runs HIBP (reused from Milestone 3, already
    optional/key-gated) + DeHashed (new, optional) + EmailRep (reused
    from Milestone 3, always runs - unauthenticated tier - and serves
    as the "local fallback" signal when neither HIBP nor DeHashed has a
    key configured, so this module never returns nothing).

    For a DOMAIN target: HIBP's public API tier has no domain-wide
    search (that requires their enterprise verified-domain ownership
    flow) and EmailRep is per-email only, so domain-wide exposure
    enumeration depends entirely on DeHashed. When DeHashed isn't
    configured for a domain target, this is reported plainly rather
    than silently returning an empty result.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)
        self.hibp = HIBPIntegration()
        self.dehashed = DeHashedIntegration()
        self.emailrep = EmailRepIntegration()

    async def investigate(
        self,
        *,
        user_id: str,
        target: str,
    ) -> Investigation:

        is_email = "@" in target

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.BREACH,
                target=target,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        if is_email:

            hibp_result, dehashed_result, emailrep_result = await asyncio.gather(
                self.hibp.run(target),
                self.dehashed.run(target),
                self.emailrep.run(target),
            )
            results = [hibp_result, dehashed_result, emailrep_result]

        else:

            dehashed_result = await self.dehashed.run(target)
            results = [dehashed_result]

        for result in results:

            self.repository.add_result(
                InvestigationResult(
                    investigation_id=investigation.id,
                    source=result.source,
                    status=result.status,
                    data=result.data,
                    latency_ms=result.latency_ms,
                    error_message=result.error_message,
                )
            )

        results_by_source = {r.source: r for r in results}

        breach_summary = self._build_breach_summary(target, is_email, results_by_source)

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="breach_summary",
                status=ModuleResultStatus.SUCCESS,
                data=breach_summary,
            )
        )

        risk_score, risk_notes = self._compute_risk_score(breach_summary)
        overall_status = self._overall_status(results)
        summary = self._build_summary(target, breach_summary, risk_notes)

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------
    # Breach Timeline / Exposed Emails / Exposed Domains /
    # Password Exposure Status
    # ------------------------------------------------------

    def _build_breach_summary(
        self,
        target: str,
        is_email: bool,
        results: dict[str, IntegrationResult],
    ) -> dict:

        timeline: list[dict] = []
        exposed_emails: set[str] = set()
        exposed_domains: set[str] = set()
        breach_names: set[str] = set()
        password_exposure_status = "not_exposed"
        local_fallback_used = False

        hibp = results.get("hibp")

        if hibp and hibp.status == ModuleResultStatus.SUCCESS and hibp.data:

            exposed_emails.add(target)

            for breach in hibp.data.get("breaches", []):

                breach_names.add(breach.get("name", "unknown"))

                if breach.get("domain"):
                    exposed_domains.add(breach["domain"])

                timeline.append(
                    {
                        "source": "hibp",
                        "breach_name": breach.get("name"),
                        "breach_date": breach.get("breach_date"),
                        "domain": breach.get("domain"),
                        "data_classes": breach.get("data_classes", []),
                        "is_sensitive": breach.get("is_sensitive"),
                    }
                )

            if hibp.data.get("breach_count", 0) > 0:
                password_exposure_status = "confirmed_breached_hibp"

        dehashed = results.get("dehashed")

        if dehashed and dehashed.status == ModuleResultStatus.SUCCESS and dehashed.data:

            exposed_emails.update(dehashed.data.get("exposed_emails", []))
            exposed_domains.update(dehashed.data.get("exposed_domains", []))
            breach_names.update(dehashed.data.get("breached_databases", []))

            for db_name in dehashed.data.get("breached_databases", []):

                timeline.append(
                    {
                        "source": "dehashed",
                        "breach_name": db_name,
                        "breach_date": None,  # DeHashed entries aren't reliably dated
                        "domain": None,
                        "data_classes": [],
                        "is_sensitive": None,
                    }
                )

            if dehashed.data.get("has_plaintext_password_exposure"):
                password_exposure_status = "confirmed_plaintext"

            elif (
                dehashed.data.get("has_hashed_password_exposure")
                and password_exposure_status == "not_exposed"
            ):
                password_exposure_status = "confirmed_hashed"

        emailrep = results.get("emailrep")

        if (
            emailrep
            and emailrep.status == ModuleResultStatus.SUCCESS
            and emailrep.data
            and password_exposure_status == "not_exposed"
        ):

            if emailrep.data.get("data_breach") or emailrep.data.get("credentials_leaked"):

                local_fallback_used = True
                password_exposure_status = "possibly_exposed_local_signal"
                exposed_emails.add(target)

        # Sort the timeline with dated entries first (most recent
        # first), undated entries appended at the end.
        timeline.sort(
            key=lambda e: (e["breach_date"] is None, e["breach_date"] or ""),
            reverse=False,
        )
        dated = [e for e in timeline if e["breach_date"]]
        undated = [e for e in timeline if not e["breach_date"]]
        dated.sort(key=lambda e: e["breach_date"], reverse=True)
        timeline = dated + undated

        return {
            "target": target,
            "is_email": is_email,
            "breach_timeline": timeline,
            "exposed_emails": sorted(exposed_emails),
            "exposed_domains": sorted(exposed_domains),
            "breach_names": sorted(breach_names),
            "total_breaches": len(breach_names),
            "password_exposure_status": password_exposure_status,
            "local_fallback_used": local_fallback_used,
        }

    # ------------------------------------------------------
    # Risk Score
    # ------------------------------------------------------

    def _compute_risk_score(self, breach_summary: dict) -> tuple[float, list[str]]:

        score = 0.0
        notes: list[str] = []

        total_breaches = breach_summary["total_breaches"]

        if total_breaches:
            score += clamp(total_breaches * 8, high=50)
            notes.append(f"Found in {total_breaches} known breach(es)/dataset(s)")

        status = breach_summary["password_exposure_status"]

        if status == "confirmed_plaintext":
            score += 35
            notes.append("Plaintext password exposed in a breach dataset")

        elif status == "confirmed_hashed":
            score += 20
            notes.append("Hashed password exposed in a breach dataset")

        elif status == "confirmed_breached_hibp":
            score += 15
            notes.append("Confirmed present in HaveIBeenPwned breach data")

        elif status == "possibly_exposed_local_signal":
            score += 10
            notes.append(
                "Local fallback signal (EmailRep) suggests possible past "
                "breach exposure - not independently confirmed"
            )

        return clamp(score), notes

    def _overall_status(self, results: list[IntegrationResult]) -> InvestigationStatus:

        actionable = [r for r in results if r.status != ModuleResultStatus.SKIPPED]

        if not actionable:
            return InvestigationStatus.FAILED

        if all(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.FAILED

        if any(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.PARTIAL

        return InvestigationStatus.COMPLETED

    def _build_summary(
        self,
        target: str,
        breach_summary: dict,
        risk_notes: list[str],
    ) -> str:

        if not risk_notes:
            return f"No breach exposure found for '{target}'."

        return f"Breach findings for '{target}': " + "; ".join(risk_notes) + "."
