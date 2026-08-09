import asyncio
from datetime import datetime
from datetime import timezone
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain.dns_integration import DNSLookupIntegration
from backend.app.integrations.domain.ssl_integration import SSLCertificateIntegration
from backend.app.integrations.domain.technology_integration import TechnologyDetectionIntegration
from backend.app.integrations.domain.whois_integration import WHOISIntegration
from backend.app.integrations.threat.otx_integration import OTXIntegration
from backend.app.integrations.url.http_response_integration import HttpResponseIntegration
from backend.app.integrations.url.urlscan_integration import URLScanIntegration
from backend.app.integrations.url.virustotal_url_integration import VirusTotalURLIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

# Providers named in the product spec that have no implementation
# anywhere in this repository (confirmed - no safe_browsing/phishtank
# integration file exists). Listed as unavailable rather than silently
# omitted, exactly like an unconfigured provider from the UI's point
# of view - but tracked separately here so the code is honest about
# *why*: not a missing API key, simply not built yet.
_NOT_IMPLEMENTED_PROVIDERS = ("google_safe_browsing", "phishtank")

# Domain-level context is REUSED from Milestone 4 (same single-
# responsibility rationale as ip_service.py) - run against the URL's
# extracted host, not reimplemented here. OTX added here (reused
# unmodified from Threat Intelligence) since it already accepts a
# domain target.
_DOMAIN_CONTEXT_ENGINES = [
    WHOISIntegration(),
    DNSLookupIntegration(),
    SSLCertificateIntegration(),
    TechnologyDetectionIntegration(),
    OTXIntegration(),
]

# HttpResponseIntegration added here: a direct, SSRF-safe fetch of the
# URL itself, giving redirect chain / HTTP status / security headers /
# page title / favicon - none of which any existing integration
# collected. See http_response_integration.py for why it isn't built
# on top of the shared request_with_retry redirect loop.
_URL_SPECIFIC_ENGINES = [
    VirusTotalURLIntegration(),
    URLScanIntegration(),
    HttpResponseIntegration(),
]


class URLIntelligenceService:
    """
    Orchestrates Milestone 5's URL Intelligence: the URL's domain is
    checked with Milestone 4's WHOIS/DNS/SSL/technology integrations for
    infrastructure context, while VirusTotal and URLScan analyze the
    specific link (redirect chain, live-rendered verdict). All run
    concurrently and persist into one Investigation.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        url: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.URL,
                target=url,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        host = urlparse(url).hostname or url

        domain_results, url_results = await asyncio.gather(
            asyncio.gather(*(engine.run(host) for engine in _DOMAIN_CONTEXT_ENGINES)),
            asyncio.gather(*(engine.run(url) for engine in _URL_SPECIFIC_ENGINES)),
        )

        engine_results: list[IntegrationResult] = [*domain_results, *url_results]
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

        assessment = _build_threat_assessment(results_by_source)
        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="threat_assessment",
                status=ModuleResultStatus.SUCCESS,
                data=assessment.data,
            )
        )

        summary = _build_summary(
            assessment_data=assessment.data,
            results=results_by_source,
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

        score = 0.0
        notes: list[str] = []

        virustotal = results.get("virustotal_url")

        if virustotal and virustotal.status == ModuleResultStatus.SUCCESS and virustotal.data:

            stats = virustotal.data.get("analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious:
                score += clamp(malicious * 6, high=40)
                notes.append(f"{malicious} VirusTotal vendor(s) flagged malicious")

            if suspicious:
                score += clamp(suspicious * 3, high=15)
                notes.append(f"{suspicious} VirusTotal vendor(s) flagged suspicious")

        urlscan = results.get("urlscan")

        if urlscan and urlscan.status == ModuleResultStatus.SUCCESS and urlscan.data:

            if urlscan.data.get("malicious"):
                score += 30
                notes.append("URLScan verdict: malicious")

        ssl_result = results.get("ssl_certificate")

        if ssl_result and ssl_result.status == ModuleResultStatus.SUCCESS and ssl_result.data:

            if not ssl_result.data.get("certificate_valid", True):
                score += 15
                notes.append("TLS certificate failed verification")

        return clamp(score), notes


# ==========================================================
# Evidence-backed assessment (replaces bare Risk Score as the
# primary conclusion for URL Investigation - see production-polish
# spec item 1)
# ==========================================================


def _build_threat_assessment(
    results: dict[str, IntegrationResult],
) -> IntegrationResult:
    """
    States: malicious, suspicious, no_malicious_evidence_detected,
    inconclusive, threat_assessment_incomplete - mirroring
    DomainIntelligenceService._build_threat_assessment's exact
    semantics and the same never-say-"safe" rule. Signals are drawn
    from VirusTotal's analysis_stats, URLScan's verdict, and OTX's
    pulse_count - the same real fields _compute_risk_score already
    uses/reuses, just expressed as a discrete state instead of a
    number.
    """

    reasoning: list[str] = []
    providers_consulted: list[str] = []
    providers_unavailable: list[str] = list(_NOT_IMPLEMENTED_PROVIDERS)
    providers_failed: list[str] = []

    virustotal = results.get("virustotal_url")
    urlscan = results.get("urlscan")
    otx = results.get("otx")

    for name, result in (
        ("virustotal_url", virustotal),
        ("urlscan", urlscan),
        ("otx", otx),
    ):
        if result is None or result.status == ModuleResultStatus.SKIPPED:
            providers_unavailable.append(name)
        elif result.status == ModuleResultStatus.FAILED:
            providers_failed.append(name)
        elif result.status == ModuleResultStatus.SUCCESS:
            providers_consulted.append(name)
        # NOT_FOUND (e.g. VT "just submitted, no verdict yet") is
        # neither consulted-with-a-verdict nor unavailable/failed -
        # it deliberately falls into neither bucket, since it's
        # genuinely a different situation from both.

    malicious_signal = False
    suspicious_signal = False

    if virustotal and virustotal.status == ModuleResultStatus.SUCCESS and virustotal.data:

        stats = virustotal.data.get("analysis_stats", {}) or {}
        malicious = stats.get("malicious", 0) or 0
        suspicious = stats.get("suspicious", 0) or 0
        total = sum(v for v in stats.values() if isinstance(v, int))

        if malicious:
            malicious_signal = True
            reasoning.append(
                f"{malicious}/{total} VirusTotal vendors flagged this URL as malicious"
                if total
                else f"{malicious} VirusTotal vendor(s) flagged this URL as malicious"
            )
        elif suspicious:
            suspicious_signal = True
            reasoning.append(f"{suspicious} VirusTotal vendor(s) flagged this URL as suspicious")

    if urlscan and urlscan.status == ModuleResultStatus.SUCCESS and urlscan.data:

        if urlscan.data.get("malicious"):
            malicious_signal = True
            categories = urlscan.data.get("verdict_categories") or []
            reasoning.append(
                "URLScan verdict: malicious"
                + (f" ({', '.join(categories)})" if categories else "")
            )

    if otx and otx.status == ModuleResultStatus.SUCCESS and otx.data:

        pulse_count = otx.data.get("pulse_count", 0)

        if pulse_count:
            suspicious_signal = True
            reasoning.append(f"Referenced in {pulse_count} AlienVault OTX threat pulse(s)")

    if not providers_consulted and not providers_failed:
        state = "threat_assessment_incomplete"
        label = "Threat assessment incomplete"
        reasoning.append("No threat intelligence provider was configured to run.")

    elif not providers_consulted and providers_failed:
        state = "inconclusive"
        label = "Insufficient evidence"
        reasoning.append(
            f"Provider(s) attempted but did not complete: {', '.join(providers_failed)}."
        )

    elif malicious_signal:
        state = "malicious"
        label = "Malicious indicators detected"

    elif suspicious_signal:
        state = "suspicious"
        label = "Suspicious indicators detected"

    else:
        state = "no_malicious_evidence_detected"
        label = "No malicious evidence detected"

        if providers_failed:
            reasoning.append(
                f"Note: {', '.join(providers_failed)} did not complete and "
                "were not part of this assessment."
            )

    return IntegrationResult(
        source="threat_assessment",
        status=ModuleResultStatus.SUCCESS,
        data={
            "state": state,
            "label": label,
            "reasoning": reasoning,
            "providers_consulted": providers_consulted,
            "providers_unavailable": providers_unavailable,
            "providers_failed": providers_failed,
        },
    )


def _build_summary(
    *,
    assessment_data: dict,
    results: dict[str, IntegrationResult],
) -> str:
    """
    An analyst-style conclusion (what was found / checked /
    unavailable), replacing the old "No notable risk signals found"
    placeholder - matches the production-polish spec's example almost
    field for field.
    """

    state = assessment_data.get("state", "threat_assessment_incomplete")
    label = assessment_data.get("label", "Threat assessment incomplete")

    sentences = ["URL successfully analyzed."]

    http_response = results.get("http_response")

    if http_response and http_response.status == ModuleResultStatus.SUCCESS and http_response.data:

        final_url = http_response.data.get("final_url")
        canonical_host = http_response.data.get("canonical_host")

        if final_url:
            sentences.append(f"The destination resolves to {canonical_host or final_url}.")

    ssl_result = results.get("ssl_certificate")

    if ssl_result and ssl_result.status == ModuleResultStatus.SUCCESS and ssl_result.data:

        if ssl_result.data.get("is_expired"):
            sentences.append("The TLS certificate has expired.")
        elif ssl_result.data.get("certificate_valid") is False:
            sentences.append("The TLS certificate failed verification.")
        elif ssl_result.data.get("certificate_valid"):
            sentences.append("TLS certificate is valid.")

    dns_result = results.get("dns_lookup")
    whois_result = results.get("whois")

    dns_ok = dns_result and dns_result.status == ModuleResultStatus.SUCCESS
    whois_ok = whois_result and whois_result.status == ModuleResultStatus.SUCCESS

    if dns_ok and whois_ok:
        sentences.append("DNS and WHOIS information were successfully collected.")
    elif dns_ok:
        sentences.append("DNS information was successfully collected.")
    elif whois_ok:
        sentences.append("WHOIS information was successfully collected.")

    if state == "threat_assessment_incomplete":
        sentences.append("No threat intelligence providers were configured.")
        sentences.append(
            "No definitive security conclusion can be made without them."
        )

    elif state == "no_malicious_evidence_detected":
        sentences.append(
            "No malicious indicators were observed from the available passive intelligence."
        )

    elif state == "inconclusive":
        sentences.append(
            "Threat intelligence providers were attempted but did not complete; "
            "no definitive security conclusion can be made."
        )

    elif state in ("malicious", "suspicious"):
        sentences.append(f"{label}.")
        reasoning = assessment_data.get("reasoning", [])
        if reasoning:
            sentences.append("Basis: " + "; ".join(reasoning) + ".")

    return " ".join(sentences)
