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

# Domain-level context is REUSED from Milestone 4 (same single-
# responsibility rationale as ip_service.py) - run against the URL's
# extracted host, not reimplemented here.
_DOMAIN_CONTEXT_ENGINES = [
    WHOISIntegration(),
    DNSLookupIntegration(),
    SSLCertificateIntegration(),
    TechnologyDetectionIntegration(),
]

_URL_SPECIFIC_ENGINES = [
    VirusTotalURLIntegration(),
    URLScanIntegration(),
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
        summary = self._build_summary(url, risk_notes)

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

    def _build_summary(
        self,
        url: str,
        risk_notes: list[str],
    ) -> str:

        if not risk_notes:
            return f"No notable risk signals found for '{url}'."

        return f"Risk signals for '{url}': " + "; ".join(risk_notes) + "."
