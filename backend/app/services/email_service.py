import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.core.intelligence.evidence import from_module_result_status
from backend.app.core.intelligence.status_semantics import InvestigationStatusOutcome
from backend.app.core.intelligence.status_semantics import determine_status_from_evidence_states
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

# Provider Status categorization (spec section 7) - a static lookup
# rather than a field on every integration class, so this one file is
# the single place that changes when a source is recategorized.
_PROVIDER_CATEGORY: dict[str, str] = {
    "mx_lookup": "email_validation",
    "disposable_email": "email_validation",
    "account_presence": "account_presence",
    "emailrep": "reputation",
    "gravatar": "identity",
    "hibp": "breach_intelligence",
    "ghunt": "identity",
}


def _with_category(result: IntegrationResult) -> IntegrationResult:
    """
    Backfills `category` from the static _PROVIDER_CATEGORY lookup when
    an engine result didn't set one itself. Non-destructive - a result
    that already set its own category is left untouched.
    """

    if result.category is None:
        result.category = _PROVIDER_CATEGORY.get(result.source)

    return result


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
        informational_findings = self._compute_informational_findings(results_by_source)

        overall_status = self._overall_status(engine_results)

        summary = self._build_summary(
            email, results_by_source, risk_notes, presence_summary,
            informational_findings=informational_findings,
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
                    # Configuration/hygiene findings (e.g. missing MX) -
                    # kept in their own key, never merged into
                    # contributing_evidence, so nothing downstream can
                    # mistake "hygiene" for "risk" (audit finding).
                    "informational_findings": informational_findings,
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

        # Provider Status (spec section 7/11): one row per engine with
        # the full status envelope (category/latency/timestamp/
        # confidence/error reason/configuration reason), so the
        # frontend can render a Provider Status section without
        # re-deriving it from each raw per-source result.
        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="provider_status",
                status=ModuleResultStatus.SUCCESS,
                data={
                    "providers": [
                        _with_category(r).to_provider_status_dict()
                        for r in engine_results
                    ],
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

    def _overall_status(
        self,
        engine_results: list[IntegrationResult],
    ) -> InvestigationStatus:
        """
        Delegates to the shared status_semantics.determine_status(),
        which treats ANY non-conclusive provider-level result (FAILED,
        RATE_LIMITED, UNABLE_TO_VERIFY, NO_DATA, PARTIAL) the same way
        for this purpose - none of them is a completed observation.
        Previously this only special-cased ModuleResultStatus.FAILED
        specifically, which would have silently mis-reported an
        investigation as COMPLETED if every non-conclusive provider
        happened to be RATE_LIMITED rather than FAILED (a real, latent
        gap - see base.py's IntegrationResult, which now actually
        returns RATE_LIMITED instead of collapsing it into FAILED).
        """

        evidence_states = [
            from_module_result_status(r.status)
            for r in engine_results
            if r.status != ModuleResultStatus.SKIPPED
        ]

        outcome = determine_status_from_evidence_states(evidence_states)

        return {
            InvestigationStatusOutcome.COMPLETED: InvestigationStatus.COMPLETED,
            InvestigationStatusOutcome.PARTIAL: InvestigationStatus.PARTIAL,
            InvestigationStatusOutcome.FAILED: InvestigationStatus.FAILED,
        }[outcome]

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
        provider being SKIPPED (e.g. ghunt with no session
        configured), RATE_LIMITED, or FAILED never subtracts or adds
        either - only conclusive SUCCESS data above contributes.
        Missing MX records are also never scored here - see
        _compute_informational_findings.
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

        return clamp(score), notes

    def _compute_informational_findings(
        self,
        results: dict[str, IntegrationResult],
    ) -> list[str]:
        """
        Configuration/hygiene findings - observations worth showing the
        investigator but that must NOT contribute to the security risk
        score (audit finding: a missing MX record was previously scored
        as +10 risk here, but a domain not accepting mail is a mail-
        configuration fact, not evidence of fraud/scam/compromise/abuse
        on its own). Kept entirely separate from _compute_risk_score's
        notes so it can never be mistaken for - or accidentally folded
        back into - a risk signal.
        """

        findings: list[str] = []

        mx = results.get("mx_lookup")

        if mx and mx.status == ModuleResultStatus.NOT_FOUND:
            findings.append("domain does not accept mail (no MX records)")

        return findings

    def _build_summary(
        self,
        email: str,
        results: dict[str, IntegrationResult],
        risk_notes: list[str],
        presence_summary: dict,
        informational_findings: list[str] | None = None,
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

        `informational_findings` (e.g. missing MX) never changes which
        of the four cases fires - they are configuration/hygiene facts,
        not risk signals - and is only ever appended as a trailing,
        clearly-labeled sentence.
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

        if informational_findings:
            message += (
                " Configuration/hygiene note(s) (not a security risk): "
                + "; ".join(informational_findings) + "."
            )

        return message
