from backend.app.utils.ip_classification import analyst_guidance_for
from backend.app.utils.ip_classification import classify_ip
from backend.app.utils.ip_classification import is_routable_public
from backend.app.utils.ip_classification import IPAddressCategory
from backend.app.utils.threat_assessment import build_analyst_summary
from backend.app.utils.threat_assessment import determine_threat_assessment
from backend.app.utils.threat_assessment import display_label
from backend.app.utils.threat_assessment import ReputationFinding
from backend.app.utils.threat_assessment import ThreatAssessment


# ==========================================================
# IP classification (private/reserved/special-use detection)
# ==========================================================

def test_rfc1918_private_ranges():

    for ip in ("192.168.1.1", "10.0.0.1", "172.16.0.1"):
        assert classify_ip(ip) == IPAddressCategory.PRIVATE


def test_loopback():

    assert classify_ip("127.0.0.1") == IPAddressCategory.LOOPBACK
    assert classify_ip("::1") == IPAddressCategory.LOOPBACK


def test_link_local():

    assert classify_ip("169.254.1.1") == IPAddressCategory.LINK_LOCAL
    assert classify_ip("fe80::1") == IPAddressCategory.LINK_LOCAL


def test_carrier_grade_nat_not_covered_by_stdlib_is_private():
    """
    Regression test for the specific stdlib gap this module exists to
    fix: Python's ipaddress.is_private does NOT flag RFC 6598 CGNAT
    addresses at all.
    """

    assert classify_ip("100.64.0.1") == IPAddressCategory.CARRIER_GRADE_NAT
    assert classify_ip("100.100.100.100") == IPAddressCategory.CARRIER_GRADE_NAT
    assert classify_ip("100.127.255.255") == IPAddressCategory.CARRIER_GRADE_NAT  # top of the /10


def test_just_outside_cgnat_range_is_public():

    assert classify_ip("100.128.0.1") == IPAddressCategory.PUBLIC
    assert classify_ip("100.63.255.255") == IPAddressCategory.PUBLIC


def test_documentation_ranges():

    assert classify_ip("192.0.2.1") == IPAddressCategory.DOCUMENTATION
    assert classify_ip("198.51.100.1") == IPAddressCategory.DOCUMENTATION
    assert classify_ip("203.0.113.1") == IPAddressCategory.DOCUMENTATION
    assert classify_ip("2001:db8::1") == IPAddressCategory.DOCUMENTATION


def test_multicast_and_broadcast():

    assert classify_ip("224.0.0.1") == IPAddressCategory.MULTICAST
    assert classify_ip("255.255.255.255") == IPAddressCategory.BROADCAST


def test_unspecified():

    assert classify_ip("0.0.0.0") == IPAddressCategory.UNSPECIFIED
    assert classify_ip("::") == IPAddressCategory.UNSPECIFIED


def test_ipv6_unique_local_is_private():

    assert classify_ip("fc00::1") == IPAddressCategory.PRIVATE


def test_public_ips_classified_correctly():

    for ip in ("8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"):
        assert classify_ip(ip) == IPAddressCategory.PUBLIC


def test_only_public_has_no_guidance_text():

    assert analyst_guidance_for(IPAddressCategory.PUBLIC) is None

    for category in IPAddressCategory:
        if category != IPAddressCategory.PUBLIC:
            assert analyst_guidance_for(category) is not None


def test_is_routable_public_excludes_cgnat():

    assert is_routable_public("8.8.8.8") is True
    assert is_routable_public("192.168.1.1") is False
    assert is_routable_public("100.64.0.1") is False


# ==========================================================
# Qualitative threat assessment (replaces numeric risk score)
# ==========================================================

def test_no_providers_configured_is_insufficient_evidence():

    findings = [
        ReputationFinding("abuseipdb", configured=False, reached=False),
        ReputationFinding("virustotal_ip", configured=False, reached=False),
    ]

    assert determine_threat_assessment(findings) == ThreatAssessment.INSUFFICIENT_EVIDENCE


def test_all_clean_and_reached_is_no_malicious_evidence():

    findings = [
        ReputationFinding("abuseipdb", configured=True, reached=True),
        ReputationFinding("virustotal_ip", configured=True, reached=True),
    ]

    assert determine_threat_assessment(findings) == ThreatAssessment.NO_MALICIOUS_EVIDENCE


def test_one_malicious_finding_is_never_diluted_by_clean_ones():

    findings = [
        ReputationFinding("abuseipdb", configured=True, reached=True, malicious=True),
        ReputationFinding("virustotal_ip", configured=True, reached=True, malicious=False),
    ]

    assert determine_threat_assessment(findings) == ThreatAssessment.MALICIOUS_DETECTED


def test_suspicious_without_malicious():

    findings = [ReputationFinding("virustotal_ip", configured=True, reached=True, suspicious=True)]

    assert determine_threat_assessment(findings) == ThreatAssessment.SUSPICIOUS_DETECTED


def test_configured_but_unreachable_provider_is_incomplete_not_clean():
    """A provider that IS configured but fails to respond must never be silently treated as 'clean'."""

    findings = [
        ReputationFinding("abuseipdb", configured=True, reached=False),
        ReputationFinding("virustotal_ip", configured=True, reached=True),
    ]

    assert determine_threat_assessment(findings) == ThreatAssessment.INCOMPLETE


def test_malicious_signal_takes_priority_over_unreachable_provider():

    findings = [
        ReputationFinding("abuseipdb", configured=True, reached=False),
        ReputationFinding("virustotal_ip", configured=True, reached=True, malicious=True),
    ]

    assert determine_threat_assessment(findings) == ThreatAssessment.MALICIOUS_DETECTED


def test_display_labels_match_spec_wording_exactly():

    assert display_label(ThreatAssessment.MALICIOUS_DETECTED) == "Malicious indicators detected"
    assert display_label(ThreatAssessment.SUSPICIOUS_DETECTED) == "Suspicious indicators detected"
    assert display_label(ThreatAssessment.NO_MALICIOUS_EVIDENCE) == "No malicious evidence detected"
    assert display_label(ThreatAssessment.INCOMPLETE) == "Threat assessment incomplete"
    assert display_label(ThreatAssessment.INSUFFICIENT_EVIDENCE) == "Insufficient evidence"


# ==========================================================
# Analyst summary generation
# ==========================================================

def test_public_ip_summary_never_says_no_notable_risk_signals():
    """The old generic sentence must never appear again."""

    summary = build_analyst_summary(
        target="8.8.8.8", resolved_ip="8.8.8.8", is_public=True, ip_category_guidance=None,
        network_facts=["ASN information was retrieved.", "Geolocation resolved successfully."],
        reverse_dns_fact=None, threat_assessment=ThreatAssessment.NO_MALICIOUS_EVIDENCE,
        unavailable_providers=[], threat_notes=[],
    )

    assert "No notable risk signals" not in summary
    assert "Public IP successfully analyzed" in summary


def test_summary_states_when_no_providers_configured():

    summary = build_analyst_summary(
        target="8.8.8.8", resolved_ip="8.8.8.8", is_public=True, ip_category_guidance=None,
        network_facts=[], reverse_dns_fact=None,
        threat_assessment=ThreatAssessment.INSUFFICIENT_EVIDENCE,
        unavailable_providers=["VirusTotal", "AbuseIPDB", "GreyNoise", "OTX"], threat_notes=[],
    )

    assert "No threat intelligence providers were configured" in summary
    assert "No definitive security conclusion" in summary


def test_private_ip_summary_skips_network_lookup_facts():

    summary = build_analyst_summary(
        target="192.168.1.1", resolved_ip="192.168.1.1", is_public=False,
        ip_category_guidance="This is a private (RFC 1918) address...",
        network_facts=[], reverse_dns_fact=None,
        threat_assessment=ThreatAssessment.INSUFFICIENT_EVIDENCE, unavailable_providers=[], threat_notes=[],
    )

    assert "private" in summary.lower()
    assert "ASN" not in summary
    assert "Geolocation" not in summary
