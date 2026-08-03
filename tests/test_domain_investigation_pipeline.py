import asyncio
from unittest.mock import AsyncMock

import pytest

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._ip_extraction import extract_public_ips
from backend.app.integrations.domain._ip_extraction import is_public_ip
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.domain_service import DomainIntelligenceService
from backend.app.services.domain_service import _build_threat_assessment
from backend.app.services.domain_service import _compute_hygiene_score
from backend.app.services.domain_service import _build_summary
from backend.app.services.domain_service import _is_ip_literal
from backend.app.services.domain_service import _normalize_domain
from backend.app.services.domain_service import _overall_status


# ==========================================================
# Pure helpers: extract_public_ips / is_public_ip
# ==========================================================
# This is the fix for the core routing bug - IP-dependent lookups must
# receive resolved public IPs, never the domain string. These
# functions are the single source of truth for that decision, so they
# get the most thorough direct coverage.


def test_extract_public_ips_deduplicates_and_classifies():
    records = {
        "A": ["93.184.216.34", "93.184.216.34", "10.0.0.5"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946", "fe80::1"],
    }

    public, non_public = extract_public_ips(records)

    assert public == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    assert non_public == ["10.0.0.5", "fe80::1"]


def test_extract_public_ips_ipv4_and_ipv6_both_supported():
    records = {"A": ["8.8.8.8"], "AAAA": ["2001:4860:4860::8888"]}

    public, non_public = extract_public_ips(records)

    assert "8.8.8.8" in public
    assert "2001:4860:4860::8888" in public
    assert non_public == []


def test_extract_public_ips_handles_missing_and_malformed_values():
    # No AAAA key at all, and a garbage value mixed into A - must not
    # crash the pipeline.
    public, non_public = extract_public_ips({"A": ["not-an-ip", "1.1.1.1"]})

    assert public == ["1.1.1.1"]
    assert non_public == []


def test_extract_public_ips_empty_records():
    assert extract_public_ips({}) == ([], [])


def test_is_public_ip():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("10.0.0.5") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("169.254.1.1") is False
    assert is_public_ip("::1") is False
    assert is_public_ip("2606:4700:4700::1111") is True
    assert is_public_ip("not-an-ip") is False


# ==========================================================
# Domain / IP literal normalization
# ==========================================================


def test_normalize_domain_lowercases_trims_and_strips_trailing_dot():
    assert _normalize_domain("  GOOGLE.com.  ") == "google.com"


def test_is_ip_literal():
    assert _is_ip_literal("8.8.8.8") is True
    assert _is_ip_literal("10.0.0.5") is True  # literal, even if private
    assert _is_ip_literal("::1") is True
    assert _is_ip_literal("example.com") is False
    assert _is_ip_literal("") is False


# ==========================================================
# Threat assessment semantics (never "safe", never fabricated)
# ==========================================================


def test_assessment_all_providers_unavailable_is_incomplete_not_low_risk():
    result = _build_threat_assessment(
        {
            "shodan": IntegrationResult("shodan", ModuleResultStatus.SKIPPED),
            "censys": IntegrationResult("censys", ModuleResultStatus.SKIPPED),
            "greynoise": IntegrationResult("greynoise", ModuleResultStatus.SKIPPED),
            "otx": IntegrationResult("otx", ModuleResultStatus.SKIPPED),
        }
    )

    assert result.data["state"] == "threat_assessment_incomplete"
    assert "safe" not in result.data["label"].lower()
    assert "low" not in result.data["label"].lower()


def test_assessment_all_providers_failed_is_inconclusive():
    result = _build_threat_assessment(
        {
            "shodan": IntegrationResult("shodan", ModuleResultStatus.FAILED, error_message="timeout"),
            "censys": IntegrationResult("censys", ModuleResultStatus.FAILED, error_message="timeout"),
            "greynoise": IntegrationResult("greynoise", ModuleResultStatus.FAILED, error_message="timeout"),
            "otx": IntegrationResult("otx", ModuleResultStatus.FAILED, error_message="timeout"),
        }
    )

    assert result.data["state"] == "inconclusive"


def test_assessment_greynoise_malicious_classification_flags_malicious():
    result = _build_threat_assessment(
        {
            "shodan": None,
            "censys": None,
            "greynoise": IntegrationResult(
                "greynoise",
                ModuleResultStatus.SUCCESS,
                data={
                    "classification": "malicious",
                    "is_internet_noise": True,
                    "is_common_business_service": False,
                },
            ),
            "otx": IntegrationResult("otx", ModuleResultStatus.SKIPPED),
        }
    )

    assert result.data["state"] == "malicious"


def test_assessment_clean_results_are_no_malicious_evidence_not_safe():
    result = _build_threat_assessment(
        {
            "shodan": IntegrationResult("shodan", ModuleResultStatus.SUCCESS, data={"vulnerabilities": []}),
            "censys": IntegrationResult("censys", ModuleResultStatus.SUCCESS, data={}),
            "greynoise": IntegrationResult(
                "greynoise", ModuleResultStatus.NOT_FOUND, data={"classification": "unknown"}
            ),
            "otx": IntegrationResult("otx", ModuleResultStatus.NOT_FOUND, data={"pulse_count": 0}),
        }
    )

    assert result.data["state"] == "no_malicious_evidence_detected"
    # The literal word "safe" must never appear in the label - absence
    # of evidence is not evidence of absence.
    assert "safe" not in result.data["label"].lower()


def test_assessment_otx_pulses_flag_suspicious():
    result = _build_threat_assessment(
        {
            "shodan": None,
            "censys": None,
            "greynoise": None,
            "otx": IntegrationResult(
                "otx", ModuleResultStatus.SUCCESS, data={"pulse_count": 3}
            ),
        }
    )

    assert result.data["state"] == "suspicious"


# ==========================================================
# Overall status / partial semantics
# ==========================================================


def test_overall_status_skipped_only_never_degrades_to_partial():
    results = [
        IntegrationResult("whois", ModuleResultStatus.SUCCESS),
        IntegrationResult("asn_lookup", ModuleResultStatus.SKIPPED),
        IntegrationResult("reverse_dns", ModuleResultStatus.SKIPPED),
    ]

    assert _overall_status(results) == InvestigationStatus.COMPLETED


def test_overall_status_one_real_failure_is_partial():
    results = [
        IntegrationResult("whois", ModuleResultStatus.SUCCESS),
        IntegrationResult("dns_lookup", ModuleResultStatus.FAILED),
        IntegrationResult("ssl_certificate", ModuleResultStatus.SKIPPED),
    ]

    assert _overall_status(results) == InvestigationStatus.PARTIAL


def test_overall_status_all_failed_is_failed():
    results = [
        IntegrationResult("whois", ModuleResultStatus.FAILED),
        IntegrationResult("dns_lookup", ModuleResultStatus.FAILED),
    ]

    assert _overall_status(results) == InvestigationStatus.FAILED


def test_overall_status_not_found_does_not_degrade_status():
    # An unregistered domain (WHOIS NOT_FOUND) or non-resolving domain
    # (DNS NOT_FOUND) is a real finding, not a pipeline failure.
    results = [
        IntegrationResult("whois", ModuleResultStatus.NOT_FOUND),
        IntegrationResult("dns_lookup", ModuleResultStatus.NOT_FOUND),
    ]

    assert _overall_status(results) == InvestigationStatus.COMPLETED


# ==========================================================
# Legacy hygiene score (kept for backward compatibility only)
# ==========================================================


def test_hygiene_score_flags_expired_certificate():
    score, notes = _compute_hygiene_score(
        {
            "ssl_certificate": IntegrationResult(
                "ssl_certificate",
                ModuleResultStatus.SUCCESS,
                data={"certificate_valid": True, "is_expired": True},
            ),
        }
    )

    assert score > 0
    assert any("expired" in note for note in notes)


def test_hygiene_score_zero_when_nothing_flagged():
    score, notes = _compute_hygiene_score(
        {
            "ssl_certificate": IntegrationResult(
                "ssl_certificate",
                ModuleResultStatus.SUCCESS,
                data={"certificate_valid": True, "is_expired": False},
            ),
        }
    )

    assert score == 0
    assert notes == []


# ==========================================================
# Full orchestration: the actual routing bug, end to end
# ==========================================================
#
# Uses a real db_session (so Investigation/InvestigationResult rows are
# genuinely persisted and can be inspected afterward) with every
# integration's .run() mocked, so these tests verify EXACTLY which
# target string each integration was called with - which is precisely
# the bug this track fixed.


def _canned(source: str, status=ModuleResultStatus.SUCCESS, data=None):
    return IntegrationResult(source=source, status=status, data=data or {})


def _patch_all_integrations(service, dns_data):
    service.dns_lookup.run = AsyncMock(
        return_value=_canned("dns_lookup", data={"records": dns_data, "domain_exists": True})
    )
    service.whois.run = AsyncMock(return_value=_canned("whois", data={"registered": True}))
    service.ssl_certificate.run = AsyncMock(return_value=_canned("ssl_certificate"))
    service.technology_detection.run = AsyncMock(return_value=_canned("technology_detection"))
    service.certificate_transparency.run = AsyncMock(
        return_value=_canned("certificate_transparency", data={"subdomains": []})
    )
    service.securitytrails.run = AsyncMock(
        return_value=_canned("securitytrails", status=ModuleResultStatus.SKIPPED)
    )
    service.asn_lookup.run = AsyncMock(return_value=_canned("asn_lookup"))
    service.ip_geolocation.run = AsyncMock(return_value=_canned("ip_geolocation"))
    service.reverse_dns.run = AsyncMock(return_value=_canned("reverse_dns"))
    service.shodan.run = AsyncMock(return_value=_canned("shodan", status=ModuleResultStatus.SKIPPED))
    service.censys.run = AsyncMock(return_value=_canned("censys", status=ModuleResultStatus.SKIPPED))
    service.greynoise.run = AsyncMock(return_value=_canned("greynoise", status=ModuleResultStatus.SKIPPED))
    service.otx.run = AsyncMock(return_value=_canned("otx", status=ModuleResultStatus.SKIPPED))


def test_ip_dependent_integrations_receive_resolved_ip_not_domain(db_session, test_user):
    """
    The exact bug from the task report: IP geolocation and reverse DNS
    must be called with the domain's resolved IP, never the domain
    string itself.
    """

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": ["93.184.216.34"], "AAAA": []})

    asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="example.com",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    service.dns_lookup.run.assert_awaited_once_with("example.com")
    service.asn_lookup.run.assert_awaited_once_with("93.184.216.34")
    service.ip_geolocation.run.assert_awaited_once_with("93.184.216.34")
    service.reverse_dns.run.assert_awaited_once_with("93.184.216.34")

    # Domain-scoped capabilities still receive the domain.
    service.whois.run.assert_awaited_once_with("example.com")
    service.ssl_certificate.run.assert_awaited_once_with("example.com")


def test_multiple_a_records_fan_out_ip_dependent_lookups_per_ip(db_session, test_user):

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(
        service, {"A": ["1.1.1.1", "1.0.0.1"], "AAAA": ["2606:4700:4700::1111"]}
    )

    asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="cloudflare-dns.example",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    called_ips = {call.args[0] for call in service.asn_lookup.run.await_args_list}
    assert called_ips == {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"}
    assert service.asn_lookup.run.await_count == 3
    assert service.reverse_dns.run.await_count == 3


def test_private_resolved_address_excluded_from_ip_dependent_lookups(db_session, test_user):

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": ["10.0.0.5"], "AAAA": []})

    investigation = asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="internal.example",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    # No public IP -> nothing to check. Must not silently call
    # anything with the private address.
    service.asn_lookup.run.assert_not_awaited()
    service.ip_geolocation.run.assert_not_awaited()
    service.reverse_dns.run.assert_not_awaited()

    sources = {r.source for r in investigation.results}
    assert "asn_lookup" in sources  # explicit SKIPPED placeholder, not absent
    assert "dns_resolution_notes" in sources


def test_bare_ip_target_is_treated_as_the_resolved_ip_not_dns_queried(db_session, test_user):
    """
    Regression guard: this endpoint also accepts a bare IP target
    directly (see _infer_investigation_type in endpoints/domain.py).
    A literal IP cannot be meaningfully DNS-resolved as a hostname -
    the pipeline must treat the target itself as the resolved address
    rather than querying DNS for it and finding nothing.
    """

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": [], "AAAA": []})

    asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="8.8.8.8",
            investigation_type=InvestigationType.IP_ADDRESS,
        )
    )

    service.dns_lookup.run.assert_not_awaited()
    service.asn_lookup.run.assert_awaited_once_with("8.8.8.8")
    service.ip_geolocation.run.assert_awaited_once_with("8.8.8.8")
    service.reverse_dns.run.assert_awaited_once_with("8.8.8.8")


def test_ipv6_only_domain_routes_ipv6_address_to_ip_dependent_lookups(db_session, test_user):

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": [], "AAAA": ["2606:4700:4700::1111"]})

    asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="ipv6-only.example",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    service.ip_geolocation.run.assert_awaited_once_with("2606:4700:4700::1111")
    service.reverse_dns.run.assert_awaited_once_with("2606:4700:4700::1111")


def test_investigation_result_rows_are_persisted_with_ip_suffixed_source(db_session, test_user):

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": ["93.184.216.34"], "AAAA": []})

    investigation = asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="example.com",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    sources = {r.source for r in investigation.results}
    assert "asn_lookup:93.184.216.34" in sources
    assert "ip_geolocation:93.184.216.34" in sources
    assert "reverse_dns:93.184.216.34" in sources
    assert "ip_intelligence_summary" in sources
    assert "threat_assessment" in sources


def test_investigation_summary_does_not_present_bare_risk_score_as_conclusion(db_session, test_user):

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": ["93.184.216.34"], "AAAA": []})

    investigation = asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="example.com",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    # The summary leads with the evidence-backed assessment label, not
    # a bare number.
    assert "Threat assessment incomplete" in investigation.summary
    assert "safe" not in investigation.summary.lower()


def test_assessment_labels_match_exact_required_display_text():
    """
    Production polish requirement: exact display strings, while the
    internal `state` keys (used by the frontend and by these same
    tests elsewhere) stay stable.
    """

    malicious = _build_threat_assessment(
        {
            "shodan": None,
            "censys": None,
            "greynoise": IntegrationResult(
                "greynoise",
                ModuleResultStatus.SUCCESS,
                data={"classification": "malicious", "is_internet_noise": True, "is_common_business_service": False},
            ),
            "otx": IntegrationResult("otx", ModuleResultStatus.SKIPPED),
        }
    )
    assert malicious.data["label"] == "Malicious indicators detected"

    suspicious = _build_threat_assessment(
        {
            "shodan": None,
            "censys": None,
            "greynoise": None,
            "otx": IntegrationResult("otx", ModuleResultStatus.SUCCESS, data={"pulse_count": 1}),
        }
    )
    assert suspicious.data["label"] == "Suspicious indicators detected"

    insufficient = _build_threat_assessment(
        {
            "shodan": IntegrationResult("shodan", ModuleResultStatus.FAILED, error_message="x"),
            "censys": IntegrationResult("censys", ModuleResultStatus.FAILED, error_message="x"),
            "greynoise": IntegrationResult("greynoise", ModuleResultStatus.FAILED, error_message="x"),
            "otx": IntegrationResult("otx", ModuleResultStatus.FAILED, error_message="x"),
        }
    )
    assert insufficient.data["label"] == "Insufficient evidence"
    assert insufficient.data["state"] == "inconclusive"  # internal key unchanged


# ==========================================================
# Analyst summary
# ==========================================================


def test_build_summary_matches_analyst_report_tone():

    summary = _build_summary(
        assessment_data={
            "state": "threat_assessment_incomplete",
            "label": "Threat assessment incomplete",
            "providers_consulted": [],
            "providers_unavailable": ["shodan", "censys", "greynoise", "otx"],
            "providers_failed": [],
            "reasoning": [],
        },
        hygiene_notes=[],
        public_ips=["1.2.3.4"] * 10,
        whois_data={"registered": True, "creation_date": "1997-09-15T04:00:00Z"},
        ssl_data={"certificate_valid": True, "is_expired": False},
    )

    assert "Threat assessment incomplete." in summary
    assert "resolves to 10 public IP addresses" in summary
    assert "dates back to 1997" in summary
    assert "TLS certificate is currently valid" in summary
    assert "no definitive security conclusion can be made" in summary
    assert "safe" not in summary.lower()


def test_build_summary_no_malicious_evidence_never_says_safe():

    summary = _build_summary(
        assessment_data={
            "state": "no_malicious_evidence_detected",
            "label": "No malicious evidence detected",
            "providers_consulted": ["shodan"],
            "providers_unavailable": [],
            "providers_failed": [],
            "reasoning": [],
        },
        hygiene_notes=[],
        public_ips=["1.2.3.4"],
        whois_data=None,
        ssl_data=None,
    )

    assert "safe" not in summary.lower()
    assert "No malicious indicators were identified" in summary


def test_hygiene_score_domain_does_not_resolve_affects_summary(db_session, test_user):
    """
    Regression guard: _compute_hygiene_score's 'domain does not
    resolve' check reads results by source name from a dict built in
    investigate() - it's easy to accidentally build that dict from
    only the domain_coros results and forget dns_result (which is
    fetched separately, before the concurrent group). This exercises
    the real orchestration path, not just the isolated pure function,
    so it would have caught exactly that mistake.
    """

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": [], "AAAA": []})
    service.dns_lookup.run = AsyncMock(
        return_value=_canned("dns_lookup", status=ModuleResultStatus.NOT_FOUND)
    )

    investigation = asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="nonexistent.example",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    assert "does not resolve" in investigation.summary


def test_dns_failure_prevents_ip_dependent_pipeline(db_session, test_user):

    service = DomainIntelligenceService(db_session)
    _patch_all_integrations(service, {"A": ["93.184.216.34"], "AAAA": []})
    service.dns_lookup.run = AsyncMock(
        return_value=_canned("dns_lookup", status=ModuleResultStatus.FAILED)
    )

    investigation = asyncio.run(
        service.investigate(
            user_id=test_user.id,
            target="flaky.example",
            investigation_type=InvestigationType.DOMAIN,
        )
    )

    # DNS failed outright, so there was nothing to extract IPs from -
    # IP-dependent capabilities correctly have nothing to check, and
    # the DNS failure itself should be visible in the final status.
    assert investigation.status in (InvestigationStatus.PARTIAL, InvestigationStatus.FAILED)


# ==========================================================
# Technology fingerprint coverage (production polish)
# ==========================================================
#
# The signature-matching loop in technology_integration.py is inline
# inside an HTTP-calling method, not extracted into an isolated pure
# function - these are golden-invariant checks (did the requested
# technologies actually get added to the tables, not silently
# mistyped) rather than full HTTP-mocked behavioral tests. See the
# changelog for why full behavioral coverage is a follow-up item.


def test_technology_signatures_cover_the_requested_stack():
    from backend.app.integrations.domain.technology_integration import (
        _BODY_SIGNATURES,
        _HEADER_SIGNATURES,
    )

    all_technologies = {tech for _, tech in _BODY_SIGNATURES}
    for signatures in _HEADER_SIGNATURES.values():
        all_technologies.update(tech for _, tech in signatures)

    for expected in [
        "Nginx",
        "Apache HTTP Server",
        "Microsoft IIS",
        "Cloudflare",
        "Vercel",
        "Netlify",
        "WordPress",
        "React",
        "Next.js",
        "Vue.js",
        "Angular",
        "Bootstrap",
        "jQuery",
        "Google Tag Manager",
        "Amazon CloudFront",
    ]:
        assert expected in all_technologies, f"{expected} missing from signature tables"
