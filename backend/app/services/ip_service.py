import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._resolve import resolve_to_ip
from backend.app.integrations.domain.asn_integration import ASNLookupIntegration
from backend.app.integrations.domain.geolocation_integration import IPGeolocationIntegration
from backend.app.integrations.domain.reverse_dns_integration import ReverseDNSIntegration
from backend.app.integrations.ip.abuseipdb_integration import AbuseIPDBIntegration
from backend.app.integrations.ip.virustotal_ip_integration import VirusTotalIPIntegration
from backend.app.integrations.threat.greynoise_integration import GreyNoiseIntegration
from backend.app.integrations.threat.otx_integration import OTXIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.ip_classification import analyst_guidance_for
from backend.app.utils.ip_classification import classify_ip
from backend.app.utils.ip_classification import IPAddressCategory
from backend.app.utils.threat_assessment import build_analyst_summary
from backend.app.utils.threat_assessment import determine_threat_assessment
from backend.app.utils.threat_assessment import display_label
from backend.app.utils.threat_assessment import ReputationFinding
from backend.app.utils.threat_assessment import ThreatAssessment

# "Network" group - always attempted for a public IP. Geolocation/ASN
# integrations are reused as-is from Milestone 4; ReverseDNSIntegration
# (also Milestone 4) is newly wired into the IP module here - it was
# never included before, and per this pass's requirements it must
# never affect the investigation's overall status (see _overall_status).
_GEOLOCATION_ENGINE = IPGeolocationIntegration()
_ASN_ENGINE = ASNLookupIntegration()
_REVERSE_DNS_ENGINE = ReverseDNSIntegration()

# "Threat Intelligence" group - VirusTotal + AbuseIPDB (Milestone 5,
# reused as-is) plus GreyNoise + OTX (Milestone 9 Part 5, reused as-is)
# per this pass's requirement to automatically enrich with all four
# when configured, rather than only the original two.
_REPUTATION_ENGINES = [
    AbuseIPDBIntegration(),
    VirusTotalIPIntegration(),
    GreyNoiseIntegration(),
    OTXIntegration(),
]

_PROVIDER_DISPLAY_NAMES = {
    "abuseipdb": "AbuseIPDB",
    "virustotal_ip": "VirusTotal",
    "greynoise": "GreyNoise",
    "otx": "OTX",
}


class IPIntelligenceService:
    """
    Orchestrates IP Address Investigation.

    Production polish pass: replaces the misleading numeric risk_score/
    risk_level (0 could mean "confirmed clean" or "we never checked" -
    passive OSINT cannot tell those apart) with an explicit qualitative
    ThreatAssessment plus an analyst-style summary that states plainly
    what was and wasn't checked. Reverse DNS is now included but never
    blocks the investigation's overall status - it is best-effort,
    informational evidence. Private/reserved/special-use IPs short-
    circuit external lookups entirely and return analyst guidance
    instead of attempting geolocation/ASN/reputation calls that make no
    sense for a non-routable address. Evidence is grouped into Network
    (ASN/Geolocation/Reverse DNS) and Threat Intelligence sections.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        target: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.IP_ADDRESS,
                target=target,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        resolved_ip = await resolve_to_ip(target)

        if resolved_ip is None:

            return self.repository.update(
                investigation,
                status=InvestigationStatus.FAILED,
                risk_score=None,
                risk_level=None,
                error_message=f"Could not resolve '{target}' to an IP address.",
                completed_at=datetime.now(timezone.utc),
            )

        category = classify_ip(resolved_ip)

        if category != IPAddressCategory.PUBLIC:
            return self._complete_non_public(investigation, target, resolved_ip, category)

        return await self._investigate_public_ip(investigation, target, resolved_ip)

    # ------------------------------------------------------
    # Private / reserved / special-use IPs - no external lookups
    # ------------------------------------------------------

    def _complete_non_public(
        self,
        investigation: Investigation,
        target: str,
        resolved_ip: str,
        category: IPAddressCategory,
    ) -> Investigation:

        guidance = analyst_guidance_for(category)

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="ip_classification",
                status=ModuleResultStatus.SUCCESS,
                data={
                    "ip_address": resolved_ip,
                    "category": category.value,
                    "summary": guidance,
                },
            )
        )

        summary = build_analyst_summary(
            target=target, resolved_ip=resolved_ip, is_public=False,
            ip_category_guidance=guidance, network_facts=[], reverse_dns_fact=None,
            threat_assessment=ThreatAssessment.INSUFFICIENT_EVIDENCE,
            unavailable_providers=[], threat_notes=[],
        )

        return self.repository.update(
            investigation,
            status=InvestigationStatus.COMPLETED,
            risk_score=None,
            risk_level=None,
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------
    # Public IPs - full evidence gathering
    # ------------------------------------------------------

    async def _investigate_public_ip(
        self,
        investigation: Investigation,
        target: str,
        resolved_ip: str,
    ) -> Investigation:

        geo_result, asn_result, reverse_dns_result, *reputation_results = await asyncio.gather(
            _GEOLOCATION_ENGINE.run(target),
            _ASN_ENGINE.run(target),
            _REVERSE_DNS_ENGINE.run(resolved_ip),
            *(engine.run(resolved_ip) for engine in _REPUTATION_ENGINES),
        )

        all_results: list[IntegrationResult] = [
            geo_result, asn_result, reverse_dns_result, *reputation_results,
        ]

        for result in all_results:

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

        grouped_data = {
            "network": {
                "asn": _summary_or_none(asn_result),
                "geolocation": _summary_or_none(geo_result),
                "reverse_dns": _summary_or_none(reverse_dns_result),
            },
            "threat_intelligence": {
                _PROVIDER_DISPLAY_NAMES[r.source]: _summary_or_none(r)
                for r in reputation_results
            },
        }

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="grouped_view",
                status=ModuleResultStatus.SUCCESS,
                data=grouped_data,
            )
        )

        findings = [_build_reputation_finding(r) for r in reputation_results]
        threat_assessment = determine_threat_assessment(findings)

        unavailable_providers = [
            _PROVIDER_DISPLAY_NAMES[r.source]
            for r in reputation_results
            if r.status == ModuleResultStatus.SKIPPED
        ]

        threat_notes = [
            f.detail for f in findings if f.reached and (f.malicious or f.suspicious) and f.detail
        ]

        network_facts = [_network_fact(asn_result, "ASN"), _network_fact(geo_result, "Geolocation")]
        network_facts = [f for f in network_facts if f]

        reverse_dns_fact = _reverse_dns_fact(reverse_dns_result)

        summary = build_analyst_summary(
            target=target, resolved_ip=resolved_ip, is_public=True, ip_category_guidance=None,
            network_facts=network_facts, reverse_dns_fact=reverse_dns_fact,
            threat_assessment=threat_assessment, unavailable_providers=unavailable_providers,
            threat_notes=threat_notes,
        )

        overall_status = self._overall_status(geo_result, asn_result, reputation_results)

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="threat_assessment",
                status=ModuleResultStatus.SUCCESS,
                data={
                    "assessment": threat_assessment.value,
                    "assessment_label": display_label(threat_assessment),
                    "unavailable_providers": unavailable_providers,
                },
            )
        )

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=None,
            risk_level=None,
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    def _overall_status(
        self,
        geo_result: IntegrationResult,
        asn_result: IntegrationResult,
        reputation_results: list[IntegrationResult],
    ) -> InvestigationStatus:
        """
        Reverse DNS is deliberately EXCLUDED from this determination
        entirely - it is optional, best-effort evidence and must never
        cause a PARTIAL or FAILED investigation on its own (see this
        module's docstring and the reverse-DNS regression tests). A
        reputation provider being unconfigured (SKIPPED) is not a
        failure either - only an actual FAILED/error result counts
        against completeness.
        """

        actionable = [geo_result, asn_result] + [
            r for r in reputation_results if r.status != ModuleResultStatus.SKIPPED
        ]

        if not actionable:
            return InvestigationStatus.FAILED

        if all(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.FAILED

        if any(r.status == ModuleResultStatus.FAILED for r in actionable):
            return InvestigationStatus.PARTIAL

        return InvestigationStatus.COMPLETED


def _summary_or_none(result: IntegrationResult) -> str | None:

    if result.data and result.data.get("summary"):
        return result.data["summary"]

    if result.status == ModuleResultStatus.SKIPPED:
        return "Unavailable - provider not configured."

    if result.status == ModuleResultStatus.FAILED:
        return result.error_message or "Temporarily unavailable."

    return None


def _network_fact(result: IntegrationResult, label: str) -> str | None:

    if result.status == ModuleResultStatus.SUCCESS:
        return f"{label} information was retrieved." if label == "ASN" else f"{label} resolved successfully."

    if result.status == ModuleResultStatus.NOT_FOUND:
        return f"No {label} record was found."

    if result.status == ModuleResultStatus.FAILED:
        return f"{label} lookup temporarily unavailable."

    return None


def _reverse_dns_fact(result: IntegrationResult) -> str | None:

    if result.status == ModuleResultStatus.SUCCESS:
        hostname = (result.data or {}).get("summary")
        return f"Reverse DNS: {hostname}." if hostname else "Reverse DNS resolved."

    if result.status == ModuleResultStatus.NOT_FOUND:
        return "No reverse DNS (PTR) record was found for this address."

    # FAILED/timeout - never block the investigation, just say so plainly.
    return "Reverse DNS lookup was unavailable."


def _build_reputation_finding(result: IntegrationResult) -> ReputationFinding:

    source = result.source
    configured = result.status != ModuleResultStatus.SKIPPED
    reached = result.status in (ModuleResultStatus.SUCCESS, ModuleResultStatus.NOT_FOUND)
    data = result.data or {}

    malicious = False
    suspicious = False
    detail = ""

    if not reached:
        return ReputationFinding(provider=source, configured=configured, reached=False)

    if source == "abuseipdb":

        score = data.get("abuse_confidence_score", 0) or 0

        if score >= 50:
            malicious = True
            detail = f"AbuseIPDB reports {score}% abuse confidence."

        elif score >= 25:
            suspicious = True
            detail = f"AbuseIPDB reports {score}% abuse confidence."

    elif source == "virustotal_ip":

        stats = data.get("analysis_stats", {}) or {}

        if stats.get("malicious", 0):
            malicious = True
            detail = f"VirusTotal: {stats.get('malicious')} vendor(s) flagged this IP malicious."

        elif stats.get("suspicious", 0):
            suspicious = True
            detail = f"VirusTotal: {stats.get('suspicious')} vendor(s) flagged this IP suspicious."

    elif source == "greynoise":

        is_riot = bool(data.get("is_common_business_service"))

        if data.get("is_internet_noise") and not is_riot:

            if data.get("classification") == "malicious":
                malicious = True
                detail = "GreyNoise classifies this IP as malicious scanning activity."

            else:
                suspicious = True
                detail = "GreyNoise observes internet-wide scanning activity from this IP."

    elif source == "otx":

        pulse_count = data.get("pulse_count", 0) or 0

        if pulse_count > 0:
            suspicious = True
            detail = f"Referenced in {pulse_count} AlienVault OTX threat pulse(s)."

    return ReputationFinding(
        provider=source, configured=configured, reached=reached,
        malicious=malicious, suspicious=suspicious, detail=detail,
    )
