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
from backend.app.integrations.email.mx_integration import MXLookupIntegration
from backend.app.integrations.email.normalization import normalize_and_correlate
from backend.app.integrations.email.normalization import summarize_findings
from backend.app.integrations.email.presence_integration import AccountPresenceIntegration
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
    AccountPresenceIntegration(),
    GHuntIntegration(),
]


class EmailIntelligenceService:
    """
    Orchestrates Email Intelligence: reputation (EmailRep), breach
    history (HIBP), Gravatar profile presence, MX/domain validity,
    disposable-address detection, native account & social presence
    checking (see integrations/email/checkers/ + normalization.py -
    architecturally modeled on the Username Intelligence module, not
    on any third-party account-checking tool/repository), and an
    optional (disabled-by-default) Google intelligence slot - run
    concurrently and persisted as one Investigation with per-source
    InvestigationResults.

    Account & social presence is profile-discovery, not threat
    scoring: finding a GitHub/Instagram/etc. account for an address
    says nothing about whether it's a security risk. risk_score is
    therefore built ONLY from actual security/breach evidence (HIBP,
    EmailRep reputation flags, disposable-address status, missing MX)
    - see _compute_risk_score, which never reads presence/Gravatar
    data at all.
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

        findings = normalize_and_correlate(
            results_by_source.get("account_presence"),
            results_by_source.get("gravatar"),
        )
        presence_summary = summarize_findings(findings)

        risk_score, risk_notes = self._compute_risk_score(results_by_source)

        overall_status = self._overall_status(engine_results)

        summary = self._build_summary(
            email, results_by_source, risk_notes, presence_summary,
        )

        # Persisted, structured explanation rows - mirrors the Domain/
        # URL/Username modules' synthesized result rows, so the
        # frontend renders "why" from real stored data instead of
        # re-parsing the prose summary string. Additive: neither is
        # scored or read by _compute_risk_score, so they can't create
        # a feedback loop.
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
                data={"email": email, **presence_summary},
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
        Builds a 0-100 exposure/risk score from breach history,
        reputation flags, and disposable-address status ONLY. Every
        contributing signal is recorded in `notes` so the summary
        stays explainable.

        Deliberately NEVER reads "account_presence" or "gravatar" data
        here: an account existing on a platform is discoverability,
        not a risk signal on its own (see module docstring). A
        provider being SKIPPED (e.g. google_intelligence with no
        session configured), RATE_LIMITED, or FAILED never subtracts
        or adds either - only conclusive SUCCESS data above
        contributes.
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
        presence_summary: dict,
    ) -> str:
        """
        Implements the four explicit summary cases:

          A. No breach/security finding + account presence confirmed
          B. Accounts only (no risk-relevant evidence at all)
          C. Confirmed breach - leads the message
          D. A risk-relevant provider (HIBP/EmailRep) didn't produce a
             conclusive result (SKIPPED/FAILED/RATE_LIMITED) and no
             positive risk evidence was found elsewhere -> providers
             unavailable, never phrased as "no breach found"

        Never claims "no breach found" if HIBP/EmailRep were not
        actually checked.
        """

        confirmed_accounts = presence_summary.get("confirmed_accounts", [])
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
            # CASE C
            message = (
                "Confirmed breach intelligence was identified. Review "
                "the affected data categories and exposure details."
            )
        elif has_unavailable_risk_source and not risk_notes:
            # CASE D
            message = (
                "Some intelligence providers were unavailable, so no "
                "definitive security conclusion can be made."
            )
        elif confirmed_accounts and not risk_notes:
            # CASE A / B (account presence identified, nothing risk-relevant)
            message = (
                f"Email account presence was identified on "
                f"{len(confirmed_accounts)} platform"
                f"{'' if len(confirmed_accounts) == 1 else 's'}. No "
                "confirmed security or breach evidence was available. "
                "Account presence alone is not a security finding."
            )
        elif risk_notes:
            message = "Risk signals for '" + email + "': " + "; ".join(risk_notes) + "."
        else:
            message = f"No notable risk signals found for '{email}'."

        if confirmed_accounts and breach_notes:
            platform_names = ", ".join(p["platform"] for p in confirmed_accounts)
            message += f" Registered account(s) also detected on: {platform_names}."

        return message
