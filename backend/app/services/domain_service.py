import asyncio
import ipaddress
from dataclasses import replace
from datetime import datetime
from datetime import timezone

import dns.asyncresolver
import dns.exception
import dns.resolver
from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._ip_extraction import extract_public_ips
from backend.app.integrations.domain._ip_extraction import is_public_ip
from backend.app.integrations.domain.asn_integration import ASNLookupIntegration
from backend.app.integrations.domain.dns_integration import DNSLookupIntegration
from backend.app.integrations.domain.geolocation_integration import IPGeolocationIntegration
from backend.app.integrations.domain.reverse_dns_integration import ReverseDNSIntegration
from backend.app.integrations.domain.ssl_integration import SSLCertificateIntegration
from backend.app.integrations.domain.technology_integration import TechnologyDetectionIntegration
from backend.app.integrations.domain.whois_integration import WHOISIntegration
from backend.app.integrations.dns_intel.certificate_transparency_integration import (
    CertificateTransparencyIntegration,
)
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

# Capabilities that only make sense against the domain itself, run
# regardless of whether DNS resolution finds any public IP.
_DOMAIN_SCOPED_SOURCES = (
    "whois",
    "ssl_certificate",
    "technology_detection",
    "certificate_transparency",
    "securitytrails",
)

# Capabilities that require a resolved public IP. These are the exact
# sources that were previously fed the raw domain string - see
# ROOT CAUSE in the class docstring below.
_IP_SCOPED_BASE_SOURCES = ("asn_lookup", "ip_geolocation", "reverse_dns")
_IP_SCOPED_THREAT_SOURCES = ("shodan", "censys", "greynoise", "otx")

_SUBDOMAIN_SAMPLE_SIZE = 15
_SUBDOMAIN_RESOLUTION_TIMEOUT_SECONDS = 3.0


class DomainIntelligenceService:
    """
    Orchestrates Domain Investigation as a dependency-aware pipeline
    rather than a flat fan-out of unrelated engines.

    ROOT CAUSE this replaces: the previous implementation ran every
    engine - including IP-only ones (IPGeolocationIntegration,
    ReverseDNSIntegration, ASNLookupIntegration) - with the raw domain
    string via a single `asyncio.gather(engine.run(target) for engine
    in _ENGINES)`. Reverse DNS correctly self-skipped on a non-IP
    target (SKIPPED, "Target is not an IP address"); geolocation/ASN
    each attempted their own internal single-IP resolution
    independently and redundantly, with no visibility into - or
    aggregation across - a domain that resolves to multiple addresses.

    Pipeline, in order:
      1. Normalize the domain.
      2. Resolve DNS (A/AAAA/MX/NS/TXT/CNAME/SOA/CAA) FIRST, awaited
         directly rather than gathered with everything else, because
         steps 3-5 depend on its result.
      3. Extract and deduplicate public IPs from the A/AAAA answers
         (see _ip_extraction.py). Non-public resolved addresses
         (private/reserved/etc.) are recorded, not silently dropped.
      4. Run domain-scoped capabilities (WHOIS, TLS, technology
         detection, subdomain discovery via crt.sh, SecurityTrails
         passive DNS) concurrently with IP-scoped capabilities (ASN,
         geolocation, reverse DNS, and threat/reputation providers)
         fanned out across every resolved public IP - never the
         domain string itself.
      5. Aggregate the per-IP results into one summary row, sample-
         resolve a bounded subset of discovered subdomains, and build
         an evidence-backed threat assessment state (not a bare risk
         score) from whatever threat/reputation providers actually
         ran.

    Every integration class used here already exists in the repository
    and is reused unmodified except for the three additive field
    changes documented in dns_integration.py / whois_integration.py /
    ssl_integration.py (new keys only, verified against every other
    consumer of those shared files before changing anything).
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

        self.whois = WHOISIntegration()
        self.dns_lookup = DNSLookupIntegration()
        self.ssl_certificate = SSLCertificateIntegration()
        self.technology_detection = TechnologyDetectionIntegration()
        self.certificate_transparency = CertificateTransparencyIntegration()
        self.securitytrails = SecurityTrailsIntegration()

        self.asn_lookup = ASNLookupIntegration()
        self.ip_geolocation = IPGeolocationIntegration()
        self.reverse_dns = ReverseDNSIntegration()
        self.shodan = ShodanIntegration()
        self.censys = CensysIntegration()
        self.greynoise = GreyNoiseIntegration()
        self.otx = OTXIntegration()

    # ==========================================================
    # Orchestration
    # ==========================================================

    async def investigate(
        self,
        *,
        user_id: str,
        target: str,
        investigation_type: InvestigationType,
    ) -> Investigation:

        domain = _normalize_domain(target)

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=investigation_type,
                target=domain,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        # ---- Step 1: DNS first - everything else depends on it. ----
        #
        # This endpoint also accepts a bare IP target directly (see
        # _infer_investigation_type in endpoints/domain.py - a
        # fallback for callers that POST an IP here rather than using
        # the dedicated IP investigation endpoint). A literal IP
        # cannot be meaningfully A/AAAA-resolved as a hostname, so
        # querying DNS for it would just return NXDOMAIN/NOT_FOUND and
        # - under the new pipeline - silently skip every IP-dependent
        # capability that's the entire point of investigating an IP.
        # Detect this up front and treat the target itself as the
        # resolved address instead of running it through DNS lookup.
        if is_public_ip(domain):
            dns_result = IntegrationResult(
                source="dns_lookup",
                status=ModuleResultStatus.SKIPPED,
                error_message=(
                    "Target is an IP address, not a domain; DNS record "
                    "lookup is not applicable."
                ),
            )
            self._persist(investigation.id, dns_result)
            public_ips, non_public_ips = [domain], []

        elif _is_ip_literal(domain):
            # A non-public IP literal (private/reserved/etc) submitted
            # directly - nothing to resolve, and nothing safe/useful
            # to run IP-dependent intelligence against.
            dns_result = IntegrationResult(
                source="dns_lookup",
                status=ModuleResultStatus.SKIPPED,
                error_message=(
                    "Target is an IP address, not a domain; DNS record "
                    "lookup is not applicable."
                ),
            )
            self._persist(investigation.id, dns_result)
            public_ips, non_public_ips = [], [domain]

        else:
            dns_result = await self.dns_lookup.run(domain)
            self._persist(investigation.id, dns_result)

            records = (dns_result.data or {}).get("records", {})
            public_ips, non_public_ips = extract_public_ips(records)

        # ---- Step 2: domain-scoped + IP-scoped, concurrently. ----
        domain_coros = [
            self.whois.run(domain),
            self.ssl_certificate.run(domain),
            self.technology_detection.run(domain),
            self.certificate_transparency.run(domain),
            self.securitytrails.run(domain),
        ]

        ip_jobs: list[tuple[str, str]] = []  # (base_source, ip)
        ip_coros = []

        for ip in public_ips:
            for base_source, integration in (
                ("asn_lookup", self.asn_lookup),
                ("ip_geolocation", self.ip_geolocation),
                ("reverse_dns", self.reverse_dns),
            ):
                ip_jobs.append((base_source, ip))
                ip_coros.append(integration.run(ip))

        # Threat/reputation providers run against the primary resolved
        # IP only (mirrors ThreatIntelligenceService's own single-IP
        # design) to keep provider call volume bounded rather than
        # multiplying 4 providers x every resolved address.
        primary_ip = public_ips[0] if public_ips else None

        if primary_ip:
            for base_source, integration in (
                ("shodan", self.shodan),
                ("censys", self.censys),
                ("greynoise", self.greynoise),
                ("otx", self.otx),
            ):
                ip_jobs.append((base_source, primary_ip))
                ip_coros.append(integration.run(primary_ip))

        domain_results, ip_results = await asyncio.gather(
            asyncio.gather(*domain_coros),
            asyncio.gather(*ip_coros),
        )

        for result in domain_results:
            self._persist(investigation.id, result)

        # IP-scoped results are persisted with an IP-suffixed source
        # name (e.g. "asn_lookup:93.184.216.34") so multiple resolved
        # addresses never collide under one InvestigationResult row -
        # this is the literal "aggregate results by IP" requirement,
        # made browsable per-source as well as summarized below.
        ip_results_by_ip: dict[str, dict[str, IntegrationResult]] = {}

        for (base_source, ip), result in zip(ip_jobs, ip_results):
            suffixed = replace(result, source=f"{base_source}:{ip}")
            self._persist(investigation.id, suffixed)
            ip_results_by_ip.setdefault(ip, {})[base_source] = result

        # A domain with no public IP shouldn't silently have these
        # capabilities vanish - record a truthful, explicit SKIPPED
        # entry so evidence coverage stays visible, per the same
        # "not applicable != no finding" principle as an unconfigured
        # provider.
        if not public_ips:
            for base_source in _IP_SCOPED_BASE_SOURCES + _IP_SCOPED_THREAT_SOURCES:
                self._persist(
                    investigation.id,
                    IntegrationResult(
                        source=base_source,
                        status=ModuleResultStatus.SKIPPED,
                        error_message=(
                            "No public IP address resolved for this domain; "
                            "nothing to check."
                        ),
                    ),
                )

        # ---- Step 3: DNS resolution notes (non-public addresses). ----
        if non_public_ips:
            self._persist(
                investigation.id,
                IntegrationResult(
                    source="dns_resolution_notes",
                    status=ModuleResultStatus.SUCCESS,
                    data={
                        "public_ips": public_ips,
                        "non_public_ips_excluded": non_public_ips,
                        "reason": (
                            "These resolved addresses are private, reserved, "
                            "loopback, or otherwise non-public, so IP-dependent "
                            "intelligence (ASN, geolocation, reverse DNS, threat "
                            "providers) was not run against them."
                        ),
                    },
                ),
            )

        # ---- Step 4: subdomain resolution sample. ----
        ct_result = next(
            (r for r in domain_results if r.source == "certificate_transparency"),
            None,
        )
        subdomain_sample = await self._sample_subdomain_resolution(ct_result)

        if subdomain_sample is not None:
            self._persist(investigation.id, subdomain_sample)

        # ---- Step 5: per-IP aggregate summary. ----
        ip_summary = _build_ip_summary(public_ips, non_public_ips, ip_results_by_ip)
        self._persist(investigation.id, ip_summary)

        # ---- Step 6: evidence-backed assessment (not a bare score). ----
        domain_results_by_source = {r.source: r for r in [dns_result, *domain_results]}
        threat_results_by_source = {
            base_source: ip_results_by_ip.get(primary_ip, {}).get(base_source)
            for base_source in _IP_SCOPED_THREAT_SOURCES
        } if primary_ip else {
            base_source: IntegrationResult(
                source=base_source,
                status=ModuleResultStatus.SKIPPED,
                error_message="No public IP address resolved for this domain.",
            )
            for base_source in _IP_SCOPED_THREAT_SOURCES
        }

        assessment = _build_threat_assessment(threat_results_by_source)
        self._persist(investigation.id, assessment)

        # Legacy numeric fields, kept for backward compatibility with
        # any existing caller (list views, badges) that reads
        # risk_score/risk_level - but per the task, these are no longer
        # the PRIMARY conclusion for Domain Investigation; the
        # assessment result row and summary text are.
        risk_score, risk_notes = _compute_hygiene_score(domain_results_by_source)

        all_persisted = (
            [dns_result, *domain_results]
            + [replace(result, source=f"{base}:{ip}") for (base, ip), result in zip(ip_jobs, ip_results)]
        )

        overall_status = _overall_status(all_persisted)

        summary = _build_summary(domain, assessment.data, risk_notes, public_ips)

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    def _persist(self, investigation_id: str, result: IntegrationResult) -> None:

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation_id,
                source=result.source,
                status=result.status,
                data=result.data,
                latency_ms=result.latency_ms,
                error_message=result.error_message,
            )
        )

    async def _sample_subdomain_resolution(
        self,
        ct_result: IntegrationResult | None,
    ) -> IntegrationResult | None:
        """
        crt.sh reports subdomains that were ever *issued a certificate*
        - that's "discovered", not "currently resolves". This checks a
        bounded sample so the result can honestly distinguish
        discovered/resolved/unresolved without either querying
        hundreds of names (slow, and looks like scanning) or silently
        claiming exhaustive coverage.
        """

        if ct_result is None or not ct_result.data:
            return None

        discovered: list[str] = ct_result.data.get("subdomains", [])

        if not discovered:
            return None

        sample = discovered[:_SUBDOMAIN_SAMPLE_SIZE]

        results = await asyncio.gather(
            *(_resolves(name) for name in sample)
        )

        resolved = [name for name, ok in zip(sample, results) if ok]
        unresolved = [name for name, ok in zip(sample, results) if not ok]

        return IntegrationResult(
            source="subdomain_resolution_sample",
            status=ModuleResultStatus.SUCCESS,
            data={
                "discovered_count": len(discovered),
                "sample_size": len(sample),
                "resolved": resolved,
                "unresolved": unresolved,
                "note": (
                    f"Resolution was checked for a sample of {len(sample)} of "
                    f"{len(discovered)} discovered subdomains. This is not "
                    "exhaustive coverage of every discovered name."
                ),
            },
        )


def _normalize_domain(target: str) -> str:
    return target.strip().lower().rstrip(".")


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _resolves(hostname: str) -> bool:
    """
    Bounded, best-effort "does this name currently resolve" check.
    Never raises - any failure (NXDOMAIN, no answer, timeout, or any
    other resolver error) is treated as unresolved rather than
    propagating and aborting the whole sample.
    """

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = _SUBDOMAIN_RESOLUTION_TIMEOUT_SECONDS
    resolver.lifetime = _SUBDOMAIN_RESOLUTION_TIMEOUT_SECONDS

    try:
        await resolver.resolve(hostname, "A")
        return True

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass

    except dns.exception.DNSException:
        return False

    try:
        await resolver.resolve(hostname, "AAAA")
        return True

    except Exception:
        return False


def _build_ip_summary(
    public_ips: list[str],
    non_public_ips: list[str],
    ip_results_by_ip: dict[str, dict[str, IntegrationResult]],
) -> IntegrationResult:
    """
    One clean, aggregated-by-IP view assembled purely from the results
    already collected above - satisfies "aggregate results by IP"
    without inventing any new data. Every field here traces back to a
    real per-source IntegrationResult persisted alongside it.
    """

    ips_summary = []

    for ip in public_ips:

        per_ip = ip_results_by_ip.get(ip, {})

        def _status_and_data(source: str) -> dict:
            result = per_ip.get(source)

            if result is None:
                return {"status": "skipped"}

            return {
                "status": result.status.value,
                "data": result.data or None,
                "error_message": result.error_message,
            }

        ips_summary.append(
            {
                "ip_address": ip,
                "asn": _status_and_data("asn_lookup"),
                "geolocation": _status_and_data("ip_geolocation"),
                "reverse_dns": _status_and_data("reverse_dns"),
            }
        )

    return IntegrationResult(
        source="ip_intelligence_summary",
        status=ModuleResultStatus.SUCCESS,
        data={
            "public_ip_count": len(public_ips),
            "non_public_ip_count": len(non_public_ips),
            "ips": ips_summary,
        },
    )


def _build_threat_assessment(
    threat_results: dict[str, IntegrationResult | None],
) -> IntegrationResult:
    """
    Evidence-backed assessment state, replacing a bare risk score as
    the primary conclusion for Domain Investigation. Signal semantics
    (GreyNoise classification/RIOT, OTX pulse_count) intentionally
    mirror ThreatIntelligenceService._compute_risk_score's own
    interpretation of these same real fields, expressed as discrete
    states instead of a number.

    States: malicious, suspicious, no_malicious_evidence_detected,
    inconclusive, threat_assessment_incomplete.

    "no_malicious_evidence_detected" is never rendered or reasoned
    about as "safe" - see the label text and the frontend renderer.
    """

    reasoning: list[str] = []
    providers_consulted: list[str] = []
    providers_unavailable: list[str] = []
    providers_failed: list[str] = []

    greynoise = threat_results.get("greynoise")
    otx = threat_results.get("otx")
    shodan = threat_results.get("shodan")
    censys = threat_results.get("censys")

    for name, result in (
        ("shodan", shodan),
        ("censys", censys),
        ("greynoise", greynoise),
        ("otx", otx),
    ):
        if result is None or result.status == ModuleResultStatus.SKIPPED:
            providers_unavailable.append(name)
        elif result.status == ModuleResultStatus.FAILED:
            providers_failed.append(name)
        else:
            providers_consulted.append(name)

    malicious_signal = False
    suspicious_signal = False

    if greynoise and greynoise.status == ModuleResultStatus.SUCCESS and greynoise.data:

        is_riot = bool(greynoise.data.get("is_common_business_service"))
        classification = greynoise.data.get("classification", "unknown")

        if greynoise.data.get("is_internet_noise") and not is_riot:

            if classification == "malicious":
                malicious_signal = True
                reasoning.append(
                    "GreyNoise classifies this IP as malicious internet scanning activity"
                )

            elif classification == "unknown":
                suspicious_signal = True
                reasoning.append(
                    "GreyNoise observes unclassified internet-wide scanning from this IP"
                )

        elif is_riot:
            reasoning.append(
                "GreyNoise identifies this IP as a known, common business service"
            )

    if otx and otx.status == ModuleResultStatus.SUCCESS and otx.data:

        pulse_count = otx.data.get("pulse_count", 0)

        if pulse_count:
            suspicious_signal = True
            reasoning.append(
                f"Referenced in {pulse_count} AlienVault OTX threat pulse(s)"
            )

    if shodan and shodan.status == ModuleResultStatus.SUCCESS and shodan.data:

        vuln_count = len(shodan.data.get("vulnerabilities", []) or [])

        if vuln_count:
            suspicious_signal = True
            reasoning.append(f"Shodan lists {vuln_count} known CVE(s) against exposed services")

    # ---- Determine state ----
    if not providers_consulted and not providers_failed:
        state = "threat_assessment_incomplete"
        label = "Threat assessment incomplete"
        reasoning.append(
            "No threat/reputation provider was configured or available to run."
        )

    elif not providers_consulted and providers_failed:
        state = "inconclusive"
        label = "Inconclusive"
        reasoning.append(
            f"Provider(s) attempted but did not complete: {', '.join(providers_failed)}."
        )

    elif malicious_signal:
        state = "malicious"
        label = "Malicious"

    elif suspicious_signal:
        state = "suspicious"
        label = "Suspicious"

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


def _compute_hygiene_score(
    results: dict[str, IntegrationResult],
) -> tuple[float, list[str]]:
    """
    Kept from the original implementation, unchanged in logic: flags
    exposure/hygiene issues (expired/invalid TLS, non-resolving domain,
    unregistered domain). This backs the legacy risk_score/risk_level
    fields for backward compatibility with existing callers - it is
    NOT the primary conclusion presented for Domain Investigation
    anymore; _build_threat_assessment's evidence-backed state is.
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


def _overall_status(results: list[IntegrationResult]) -> InvestigationStatus:
    """
    Unchanged semantics from the original implementation - SKIPPED
    (not-applicable or not-configured) never counts toward degrading
    status, so a module that's inherently not applicable (e.g. ASN
    lookup for a domain with no public IP) cannot incorrectly mark the
    investigation PARTIAL. Only an actual FAILED capability does that.
    """

    actionable = [r for r in results if r.status != ModuleResultStatus.SKIPPED]

    if not actionable:
        return InvestigationStatus.FAILED

    if all(r.status == ModuleResultStatus.FAILED for r in actionable):
        return InvestigationStatus.FAILED

    if any(r.status == ModuleResultStatus.FAILED for r in actionable):
        return InvestigationStatus.PARTIAL

    return InvestigationStatus.COMPLETED


def _build_summary(
    domain: str,
    assessment_data: dict,
    hygiene_notes: list[str],
    public_ips: list[str],
) -> str:

    label = assessment_data.get("label", "Threat assessment incomplete")

    parts = [f"{label} for '{domain}'."]

    if public_ips:
        parts.append(
            f"Resolved to {len(public_ips)} public IP address"
            f"{'es' if len(public_ips) != 1 else ''}."
        )
    else:
        parts.append("No public IP address was resolved for this domain.")

    if hygiene_notes:
        parts.append("Infrastructure hygiene notes: " + "; ".join(hygiene_notes) + ".")

    return " ".join(parts)
