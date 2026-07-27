import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.dns_intel.certificate_transparency_integration import CertificateTransparencyIntegration
from backend.app.integrations.dns_intel.dmarc_integration import DMARCIntegration
from backend.app.integrations.domain.dns_integration import DNSLookupIntegration
from backend.app.integrations.threat.securitytrails_integration import SecurityTrailsIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score
from backend.app.utils.spf_analysis import analyze_spf


class DNSIntelligenceService:
    """
    Orchestrates Milestone 9 Part 6 (DNS Intelligence) for a domain
    target:

    - Name Servers / TXT / MX records: reused directly from Milestone
      4's DNSLookupIntegration - not re-fetched or reimplemented.
    - Passive/Historical DNS: reused directly from Milestone 9 Part 5's
      SecurityTrailsIntegration (optional, key-gated).
    - Certificate Transparency / Subdomain Enumeration: new, free,
      always-on (crt.sh needs no API key).
    - SPF Analysis: pure-logic parsing of the TXT records already
      fetched above - no second DNS query.
    - DMARC Analysis: new, dedicated _dmarc.{domain} TXT lookup (the
      bare-domain TXT query above never includes this record).
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)
        self.dns_lookup = DNSLookupIntegration()
        self.certificate_transparency = CertificateTransparencyIntegration()
        self.dmarc = DMARCIntegration()
        self.securitytrails = SecurityTrailsIntegration()

    async def investigate(
        self,
        *,
        user_id: str,
        domain: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.DNS,
                target=domain,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        dns_result, ct_result, dmarc_result, passive_dns_result = await asyncio.gather(
            self.dns_lookup.run(domain),
            self.certificate_transparency.run(domain),
            self.dmarc.run(domain),
            self.securitytrails.run(domain),
        )

        results = [dns_result, ct_result, dmarc_result, passive_dns_result]

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

        txt_records = []

        if dns_result.status == ModuleResultStatus.SUCCESS and dns_result.data:
            txt_records = dns_result.data.get("records", {}).get("TXT", [])

        spf_data = analyze_spf(txt_records)

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="spf_analysis",
                status=(
                    ModuleResultStatus.SUCCESS
                    if spf_data["has_spf_record"]
                    else ModuleResultStatus.NOT_FOUND
                ),
                data=spf_data,
            )
        )

        risk_score, risk_notes = self._compute_risk_score(
            dns_result,
            ct_result,
            dmarc_result,
            spf_data,
        )

        overall_status = self._overall_status(results)
        summary = self._build_summary(domain, risk_notes)

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    def _overall_status(self, results: list[IntegrationResult]) -> InvestigationStatus:

        actionable = [r for r in results if r.status != ModuleResultStatus.SKIPPED]

        if not actionable:
            return InvestigationStatus.FAILED

        if all(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.FAILED

        if any(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.PARTIAL

        return InvestigationStatus.COMPLETED

    def _compute_risk_score(
        self,
        dns_result: IntegrationResult,
        ct_result: IntegrationResult,
        dmarc_result: IntegrationResult,
        spf_data: dict,
    ) -> tuple[float, list[str]]:
        """
        Scores mail-spoofing exposure (missing/weak SPF or DMARC) and
        attack-surface size (subdomain count) - this is email-security
        and reconnaissance-surface hygiene, not a judgment of the
        domain owner.
        """

        score = 0.0
        notes: list[str] = []

        if not spf_data["has_spf_record"]:
            score += 15
            notes.append("No SPF record found - mail domain is spoofable via SPF")

        elif spf_data["all_mechanism_strength"] == "pass":
            score += 20
            notes.append("SPF record ends in '+all' - explicitly allows any sender")

        elif spf_data["all_mechanism_strength"] == "neutral":
            score += 8
            notes.append("SPF record ends in '?all' - neutral, provides little protection")

        if spf_data["exceeds_dns_lookup_limit"]:
            score += 10
            notes.append(
                "SPF record exceeds RFC 7208's 10-DNS-lookup limit - "
                "will PermError at evaluation time"
            )

        if spf_data["multiple_spf_records"]:
            score += 10
            notes.append("Multiple SPF TXT records found - invalid per RFC 7208")

        if dmarc_result.status == ModuleResultStatus.NOT_FOUND:
            score += 15
            notes.append("No DMARC record found")

        elif dmarc_result.status == ModuleResultStatus.SUCCESS and dmarc_result.data:

            policy = dmarc_result.data.get("policy")

            if policy == "none":
                score += 10
                notes.append("DMARC policy is 'p=none' - monitoring only, no enforcement")

        if ct_result.status == ModuleResultStatus.SUCCESS and ct_result.data:

            subdomain_count = ct_result.data.get("subdomain_count", 0)

            if subdomain_count >= 50:
                score += clamp((subdomain_count - 50) * 0.2, high=20)
                notes.append(
                    f"Large subdomain footprint: {subdomain_count} distinct "
                    "subdomains observed in Certificate Transparency logs"
                )

        return clamp(score), notes

    def _build_summary(self, domain: str, risk_notes: list[str]) -> str:

        if not risk_notes:
            return f"No notable DNS/mail-security risk signals found for '{domain}'."

        return f"DNS intelligence findings for '{domain}': " + "; ".join(risk_notes) + "."
