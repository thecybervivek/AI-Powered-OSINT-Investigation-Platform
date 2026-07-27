import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._resolve import resolve_to_ip
from backend.app.integrations.threat.censys_integration import CensysIntegration
from backend.app.integrations.threat.greynoise_integration import GreyNoiseIntegration
from backend.app.integrations.threat.otx_integration import OTXIntegration
from backend.app.integrations.threat.securitytrails_integration import SecurityTrailsIntegration
from backend.app.integrations.threat.shodan_integration import ShodanIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score


class ThreatIntelligenceService:
    """
    Orchestrates Milestone 9 Part 5 (Threat Intelligence): Shodan +
    Censys (host intelligence: open ports, services, ASN, org, tags) +
    GreyNoise (mass-scanner/RIOT classification) + OTX (community
    threat-pulse reputation) run against the resolved IP; SecurityTrails
    (historical/passive DNS) runs against the domain when the target is
    one. Every provider is independently optional - any subset (or all
    five) being unconfigured still leaves the investigation usable, it
    just reports fewer sources as skipped rather than failing outright.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)
        self.shodan = ShodanIntegration()
        self.censys = CensysIntegration()
        self.greynoise = GreyNoiseIntegration()
        self.otx = OTXIntegration()
        self.securitytrails = SecurityTrailsIntegration()

    async def investigate(
        self,
        *,
        user_id: str,
        target: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.THREAT_INTELLIGENCE,
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

        # Host/reputation providers run against the resolved IP;
        # SecurityTrails' historical DNS runs against the original
        # target (it self-skips for IP-literal targets - see its
        # is_configured/_query - so passing `target` here is correct
        # whether it was a domain or an IP to begin with).
        results: list[IntegrationResult] = list(
            await asyncio.gather(
                self.shodan.run(resolved_ip),
                self.censys.run(resolved_ip),
                self.greynoise.run(resolved_ip),
                self.otx.run(resolved_ip),
                self.securitytrails.run(target),
            )
        )

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

        risk_score, risk_notes = self._compute_risk_score(results_by_source)
        overall_status = self._overall_status(results)
        summary = self._build_summary(target, resolved_ip, risk_notes)

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
        results: dict[str, IntegrationResult],
    ) -> tuple[float, list[str]]:
        """
        Composite score across every configured provider. GreyNoise's
        RIOT flag (known-benign business service) is the one signal
        that actively LOWERS the score - everything else only adds, in
        proportion to how corroborated the finding is (a single OTX
        pulse counts for less than dozens referencing the same IP).
        """

        score = 0.0
        notes: list[str] = []

        greynoise = results.get("greynoise")
        is_riot = False

        if greynoise and greynoise.status == ModuleResultStatus.SUCCESS and greynoise.data:

            is_riot = bool(greynoise.data.get("is_common_business_service"))

            if greynoise.data.get("is_internet_noise") and not is_riot:

                classification = greynoise.data.get("classification", "unknown")

                if classification == "malicious":
                    score += 30
                    notes.append("GreyNoise classifies this IP as malicious internet scanning activity")

                elif classification == "unknown":
                    score += 10
                    notes.append("GreyNoise observes unclassified internet-wide scanning from this IP")

        otx = results.get("otx")

        if otx and otx.status == ModuleResultStatus.SUCCESS and otx.data:

            pulse_count = otx.data.get("pulse_count", 0)

            if pulse_count:
                score += clamp(pulse_count * 5, high=35)
                notes.append(
                    f"Referenced in {pulse_count} AlienVault OTX threat pulse(s)"
                )

        shodan = results.get("shodan")

        if shodan and shodan.status == ModuleResultStatus.SUCCESS and shodan.data:

            vuln_count = len(shodan.data.get("vulnerabilities", []))

            if vuln_count:
                score += clamp(vuln_count * 4, high=25)
                notes.append(
                    f"Shodan lists {vuln_count} known CVE(s) against exposed services"
                )

            open_port_count = len(shodan.data.get("open_ports", []))

            if open_port_count >= 10:
                score += 10
                notes.append(
                    f"Unusually large exposed surface: {open_port_count} open ports observed"
                )

        score = clamp(score)

        # A confirmed common business service (CDN, cloud provider
        # health-check, etc.) pulls the composite score down - it
        # explains away noise/scanning classifications that would
        # otherwise look concerning in isolation.
        if is_riot:

            score = clamp(score * 0.3)
            notes.append(
                "GreyNoise identifies this as a known common business "
                "service (RIOT) - score reduced accordingly"
            )

        return score, notes

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
            return f"No notable threat signals found for {prefix}."

        return f"Threat intelligence findings for {prefix}: " + "; ".join(risk_notes) + "."
