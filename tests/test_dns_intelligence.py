from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.dns_intel.certificate_transparency_integration import _parse_crtsh_response
from backend.app.integrations.dns_intel.dmarc_integration import _parse_dmarc_tags
from backend.app.integrations.dns_intel.dmarc_integration import _split_report_addresses
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import ModuleResultStatus
from backend.app.services.dns_intelligence_service import DNSIntelligenceService
from backend.app.utils.spf_analysis import analyze_spf


# ==========================================================
# SPF analysis (pure logic, no network - the one true unit here)
# ==========================================================

def test_spf_missing_record():

    result = analyze_spf(["some unrelated txt record", "google-site-verification=abc123"])

    assert result["has_spf_record"] is False
    assert result["exceeds_dns_lookup_limit"] is False


def test_spf_strict_record_counts_lookups_correctly():

    result = analyze_spf(["v=spf1 include:_spf.google.com include:sendgrid.net -all"])

    assert result["all_mechanism_qualifier"] == "-"
    assert result["all_mechanism_strength"] == "hardfail"
    assert result["dns_lookup_count"] == 2
    assert result["exceeds_dns_lookup_limit"] is False


def test_spf_all_mechanism_not_confused_with_a_mechanism():
    """
    Regression test: "all" and "a" both start with the letter "a" -
    naive prefix matching previously miscounted "all" as an extra "a"
    mechanism, inflating the DNS lookup count. Caught during Part 6
    development by actually running this exact case.
    """

    result = analyze_spf(["v=spf1 a mx +all"])

    assert result["all_mechanism_qualifier"] == "+"
    assert result["all_mechanism_strength"] == "pass"
    assert result["dns_lookup_count"] == 2  # 'a' + 'mx', NOT 3


def test_spf_ip4_ip6_never_count_as_dns_lookups():

    result = analyze_spf(["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a:mail.example.com -all"])

    assert result["dns_lookup_count"] == 1


def test_spf_exceeds_rfc7208_lookup_limit():

    many_includes = "v=spf1 " + " ".join(f"include:spf{i}.example.com" for i in range(11)) + " ~all"

    result = analyze_spf([many_includes])

    assert result["dns_lookup_count"] == 11
    assert result["exceeds_dns_lookup_limit"] is True


def test_spf_multiple_records_flagged_as_invalid():

    result = analyze_spf(["v=spf1 -all", "v=spf1 include:example.com ~all"])

    assert result["multiple_spf_records"] is True


def test_spf_neutral_qualifier():

    result = analyze_spf(["v=spf1 mx ?all"])

    assert result["all_mechanism_qualifier"] == "?"
    assert result["all_mechanism_strength"] == "neutral"


# ==========================================================
# crt.sh response parsing (pure logic)
# ==========================================================

def test_crtsh_parses_well_formed_json():

    import json

    payload = json.dumps(
        [
            {"id": 1, "name_value": "www.example.com\nexample.com", "not_before": "2023-01-01T00:00:00"},
            {"id": 2, "name_value": "*.api.example.com", "not_before": "2024-06-15T00:00:00"},
        ]
    )

    certs = _parse_crtsh_response(payload)

    assert len(certs) == 2


def test_crtsh_repairs_known_concatenation_quirk():

    malformed = (
        '{"id": 1, "name_value": "a.example.com"}'
        '{"id": 2, "name_value": "b.example.com"}'
    )

    certs = _parse_crtsh_response(malformed)

    assert len(certs) == 2


def test_crtsh_unparseable_input_returns_empty_list():

    assert _parse_crtsh_response("not json at all {{{") == []


# ==========================================================
# DMARC tag parsing (pure logic)
# ==========================================================

def test_dmarc_parses_full_record():

    record = (
        "v=DMARC1; p=reject; sp=quarantine; pct=100; "
        "rua=mailto:agg@example.com,mailto:agg2@example.com; "
        "ruf=mailto:forensic@example.com; adkim=s; aspf=r"
    )

    tags = _parse_dmarc_tags(record)

    assert tags["p"] == "reject"
    assert tags["sp"] == "quarantine"
    assert tags["adkim"] == "s"
    assert tags["aspf"] == "r"


def test_dmarc_minimal_p_none_record():

    tags = _parse_dmarc_tags("v=DMARC1; p=none")

    assert tags["p"] == "none"
    assert "rua" not in tags


def test_dmarc_report_address_splitting():

    assert _split_report_addresses("mailto:a@example.com,mailto:b@example.com") == [
        "a@example.com",
        "b@example.com",
    ]
    assert _split_report_addresses(None) == []


# ==========================================================
# DNSIntelligenceService - pure logic (no DB, no network)
# ==========================================================

def _service() -> DNSIntelligenceService:
    return DNSIntelligenceService(db=None)


def test_risk_score_zero_for_well_configured_domain():

    service = _service()

    dns_result = IntegrationResult(
        source="dns_lookup", status=ModuleResultStatus.SUCCESS,
        data={"records": {"TXT": ["v=spf1 include:_spf.google.com -all"]}},
    )
    ct_result = IntegrationResult(
        source="certificate_transparency", status=ModuleResultStatus.SUCCESS,
        data={"subdomain_count": 5},
    )
    dmarc_result = IntegrationResult(
        source="dmarc", status=ModuleResultStatus.SUCCESS,
        data={"policy": "reject"},
    )
    spf_data = analyze_spf(dns_result.data["records"]["TXT"])

    score, notes = service._compute_risk_score(dns_result, ct_result, dmarc_result, spf_data)

    assert score == 0.0
    assert notes == []


def test_risk_score_flags_missing_spf_and_dmarc():

    service = _service()

    dns_result = IntegrationResult(
        source="dns_lookup", status=ModuleResultStatus.SUCCESS,
        data={"records": {"TXT": []}},
    )
    ct_result = IntegrationResult(
        source="certificate_transparency", status=ModuleResultStatus.NOT_FOUND, data={},
    )
    dmarc_result = IntegrationResult(
        source="dmarc", status=ModuleResultStatus.NOT_FOUND, data={},
    )
    spf_data = analyze_spf([])

    score, notes = service._compute_risk_score(dns_result, ct_result, dmarc_result, spf_data)

    assert score > 0
    assert any("No SPF record" in note for note in notes)
    assert any("No DMARC record" in note for note in notes)


def test_risk_score_flags_permissive_spf_and_weak_dmarc():

    service = _service()

    dns_result = IntegrationResult(
        source="dns_lookup", status=ModuleResultStatus.SUCCESS,
        data={"records": {"TXT": ["v=spf1 a mx +all"]}},
    )
    ct_result = IntegrationResult(
        source="certificate_transparency", status=ModuleResultStatus.SUCCESS,
        data={"subdomain_count": 3},
    )
    dmarc_result = IntegrationResult(
        source="dmarc", status=ModuleResultStatus.SUCCESS,
        data={"policy": "none"},
    )
    spf_data = analyze_spf(dns_result.data["records"]["TXT"])

    score, notes = service._compute_risk_score(dns_result, ct_result, dmarc_result, spf_data)

    assert score > 0
    assert any("+all" in note for note in notes)
    assert any("p=none" in note for note in notes)


def test_risk_score_flags_large_subdomain_footprint():

    service = _service()

    dns_result = IntegrationResult(
        source="dns_lookup", status=ModuleResultStatus.SUCCESS,
        data={"records": {"TXT": ["v=spf1 -all"]}},
    )
    ct_result = IntegrationResult(
        source="certificate_transparency", status=ModuleResultStatus.SUCCESS,
        data={"subdomain_count": 120},
    )
    dmarc_result = IntegrationResult(
        source="dmarc", status=ModuleResultStatus.SUCCESS,
        data={"policy": "reject"},
    )
    spf_data = analyze_spf(dns_result.data["records"]["TXT"])

    score, notes = service._compute_risk_score(dns_result, ct_result, dmarc_result, spf_data)

    assert score > 0
    assert any("Large subdomain footprint" in note for note in notes)


def test_overall_status_completed_when_all_succeed():

    service = _service()

    results = [
        IntegrationResult(source="dns_lookup", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="certificate_transparency", status=ModuleResultStatus.SUCCESS, data={}),
        IntegrationResult(source="dmarc", status=ModuleResultStatus.NOT_FOUND, data={}),
        IntegrationResult(source="securitytrails", status=ModuleResultStatus.SKIPPED),
    ]

    assert service._overall_status(results) == InvestigationStatus.COMPLETED


def test_build_summary_no_findings():

    service = _service()

    summary = service._build_summary("example.com", risk_notes=[])

    assert "No notable DNS/mail-security risk signals" in summary
    assert "example.com" in summary
