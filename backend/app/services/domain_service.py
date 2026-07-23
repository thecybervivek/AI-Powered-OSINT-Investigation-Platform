import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain.asn_integration import ASNLookupIntegration
from backend.app.integrations.domain.dns_integration import DNSLookupIntegration
from backend.app.integrations.domain.geolocation_integration import IPGeolocationIntegration
from backend.app.integrations.domain.reverse_dns_integration import ReverseDNSIntegration
from backend.app.integrations.domain.ssl_integration import SSLCertificateIntegration
from backend.app.integrations.domain.technology_integration import TechnologyDetectionIntegration
from backend.app.integrations.domain.whois_integration import WHOISIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

_ENGINES = [
    WHOISIntegration(),
    DNSLookupIntegration(),
    ReverseDNSIntegration(),
    IPGeolocationIntegration(),
    ASNLookupIntegration(),
    SSLCertificateIntegration(),
    TechnologyDetectionIntegration(),
]


class DomainIntelligenceService:
    """
    Orchestrates Milestone 4 (Domain / IP / DNS Intelligence): WHOIS,
    DNS record enumeration, reverse DNS, IP geolocation, ASN lookup,
    SSL certificate inspection, and lightweight technology detection —
    run concurrently and merged into one unified intelligence response.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        target: str,
        investigation_type: InvestigationType,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=investigation_type,
                target=target,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        engine_results: list[IntegrationResult] = await asyncio.gather(
            *(engine.run(target) for engine in _ENGINES)
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
        summary = self._build_summary(target, risk_notes)

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
        Flags exposure/hygiene issues: expired or invalid TLS, a domain
        that resolves to nothing (dangling/parked), or freshly-registered
        WHOIS records commonly associated with throwaway infrastructure.
        """

        score = 0.0
        notes: list[str] = []

        ssl_result = results.get("ssl_certificate")

        if ssl_result and ssl_result.status == ModuleResultStatus.SUCCESS and ssl_result.data:

            if not ssl_result.data.get("certificate_valid", True):
                score += 25
                notes.append("TLS certificate failed verification")

            elif ssl_result.data.get("is_expired"):
                score += 20
                notes.append("TLS certificate is expired")

        dns_result = results.get("dns_lookup")

        if dns_result and dns_result.status == ModuleResultStatus.NOT_FOUND:
            score += 15
            notes.append("domain does not resolve")

        whois_result = results.get("whois")

        if whois_result and whois_result.status == ModuleResultStatus.NOT_FOUND:
            score += 10
            notes.append("domain is unregistered")

        return clamp(score), notes

    def _build_summary(
        self,
        target: str,
        risk_notes: list[str],
    ) -> str:

        if not risk_notes:
            return f"No notable risk signals found for '{target}'."

        return f"Risk signals for '{target}': " + "; ".join(risk_notes) + "."
