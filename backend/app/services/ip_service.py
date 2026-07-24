import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._resolve import resolve_to_ip
from backend.app.integrations.domain.asn_integration import ASNLookupIntegration
from backend.app.integrations.domain.geolocation_integration import IPGeolocationIntegration
from backend.app.integrations.ip.abuseipdb_integration import AbuseIPDBIntegration
from backend.app.integrations.ip.virustotal_ip_integration import VirusTotalIPIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

# Milestone 4 sources are REUSED here, not reimplemented - this service
# composes them with the two new reputation sources rather than
# duplicating geolocation/ASN logic (single responsibility per
# integration; this class owns only the composition + scoring).
_GEO_ENGINES = [
    IPGeolocationIntegration(),
    ASNLookupIntegration(),
]

_REPUTATION_ENGINES = [
    AbuseIPDBIntegration(),
    VirusTotalIPIntegration(),
]


class IPIntelligenceService:
    """
    Orchestrates Milestone 5's IP Intelligence: reuses Milestone 4's
    geolocation/ASN integrations for context, and adds AbuseIPDB +
    VirusTotal for reputation - all run concurrently and persisted as
    one Investigation with per-source InvestigationResults.
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
                error_message=f"Could not resolve '{target}' to an IP address.",
                completed_at=datetime.now(timezone.utc),
            )

        # Geo/ASN integrations self-resolve domains, so the original
        # target is fine for them; reputation sources require a literal
        # IP, so they get the already-resolved address.
        geo_results, reputation_results = await asyncio.gather(
            asyncio.gather(*(engine.run(target) for engine in _GEO_ENGINES)),
            asyncio.gather(*(engine.run(resolved_ip) for engine in _REPUTATION_ENGINES)),
        )

        engine_results: list[IntegrationResult] = [*geo_results, *reputation_results]
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
        summary = self._build_summary(target, resolved_ip, risk_notes)

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

        abuseipdb = results.get("abuseipdb")

        if abuseipdb and abuseipdb.status == ModuleResultStatus.SUCCESS and abuseipdb.data:

            confidence = abuseipdb.data.get("abuse_confidence_score", 0) or 0
            score += confidence  # already a 0-100 scale, dominant signal

            if confidence >= 25:
                notes.append(f"AbuseIPDB confidence score {confidence}%")

            total_reports = abuseipdb.data.get("total_reports", 0)

            if total_reports:
                notes.append(f"{total_reports} community abuse report(s)")

        virustotal = results.get("virustotal_ip")

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

        return clamp(score), notes

    def _build_summary(
        self,
        target: str,
        resolved_ip: str,
        risk_notes: list[str],
    ) -> str:

        prefix = (
            f"'{target}' (resolved to {resolved_ip})"
            if target != resolved_ip
            else f"'{resolved_ip}'"
        )

        if not risk_notes:
            return f"No notable risk signals found for {prefix}."

        return f"Risk signals for {prefix}: " + "; ".join(risk_notes) + "."
