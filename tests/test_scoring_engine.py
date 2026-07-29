from backend.app.core.intelligence.evidence import Evidence
from backend.app.core.intelligence.evidence import EvidenceState
from backend.app.core.intelligence.evidence import EvidenceType
from backend.app.core.intelligence.scoring import assess
from backend.app.core.intelligence.scoring import compute_coverage


def _ev(**kw) -> Evidence:

    defaults = dict(
        indicator="x", investigation_id="inv1", provider="p",
        evidence_type=EvidenceType.SECURITY_MALICIOUS, state=EvidenceState.SUCCESS,
        severity=0, confidence=80, source_reliability=0.8, freshness=1.0,
    )
    defaults.update(kw)

    return Evidence(**defaults)


def test_not_found_is_zero_risk_but_full_coverage():

    result = assess([_ev(state=EvidenceState.NOT_FOUND, severity=0)], expected_providers=["p"])

    assert result.security_risk.value == 0.0
    assert result.coverage.percentage == 100.0


def test_zero_providers_executed_cannot_produce_confident_benign_verdict():

    result = assess([], expected_providers=["abuseipdb", "virustotal", "greynoise"])

    assert result.coverage.percentage == 0.0
    assert result.confidence.value == 0.0
    assert result.security_risk.value == 0.0


def test_critical_signal_survives_aggregation():
    """A confirmed-critical finding must not be diluted toward 'medium' by weak corroborators."""

    evidence = [
        _ev(provider="hibp", severity=95, confidence=95, source_reliability=0.9, summary="Confirmed malicious hash"),
        _ev(provider="a", severity=5, confidence=50, source_reliability=0.6, summary="minor a"),
        _ev(provider="b", severity=5, confidence=50, source_reliability=0.6, summary="minor b"),
        _ev(provider="c", severity=5, confidence=50, source_reliability=0.6, summary="minor c"),
    ]

    result = assess(evidence, expected_providers=["hibp", "a", "b", "c"])

    assert result.security_risk.value >= 75
    assert result.security_risk.level == "CRITICAL"


def test_duplicate_evidence_does_not_inflate_score():

    dup = [_ev(provider="hibp", severity=90, confidence=90, summary="dup finding")] * 5
    single = [_ev(provider="hibp", severity=90, confidence=90, summary="dup finding")]

    assert assess(dup, ["hibp"]).security_risk.value == assess(single, ["hibp"]).security_risk.value


def test_same_provider_repetition_weaker_than_independent_corroboration():

    same_provider = [_ev(provider="p1", severity=40, confidence=70, summary=f"f{i}") for i in range(3)]
    independent = [_ev(provider=f"p{i}", severity=40, confidence=70, summary=f"f{i}") for i in range(3)]

    same_score = assess(same_provider, ["p1"]).security_risk.value
    independent_score = assess(independent, ["p0", "p1", "p2"]).security_risk.value

    assert independent_score > same_score


def test_public_profile_count_does_not_directly_equal_security_risk():

    result = assess(
        [_ev(evidence_type=EvidenceType.PUBLIC_PRESENCE, severity=60, confidence=90)],
        expected_providers=["sherlock"],
    )

    assert result.security_risk.value == 0.0
    assert result.exposure.value > 0


def test_large_dns_footprint_affects_exposure_more_than_security_risk():

    result = assess(
        [_ev(evidence_type=EvidenceType.INFRASTRUCTURE_FACT, severity=50, confidence=80)],
        expected_providers=["crtsh"],
    )

    assert result.exposure.value > result.security_risk.value


def test_coverage_counts_only_conclusive_states():

    mixed = [
        _ev(provider="vt", state=EvidenceState.SUCCESS, severity=10),
        _ev(provider="abuseipdb", state=EvidenceState.FAILED, severity=0),
        _ev(provider="greynoise", state=EvidenceState.NOT_PERFORMED, severity=0),
    ]

    coverage = compute_coverage(mixed, expected_providers=["vt", "abuseipdb", "greynoise", "otx", "censys"])

    assert coverage.executed == 1
    assert coverage.percentage == 20.0


def test_quota_exhausted_counts_as_non_executed_not_coverage():

    coverage = compute_coverage(
        [_ev(provider="shodan", state=EvidenceState.QUOTA_EXHAUSTED)],
        expected_providers=["shodan"],
    )

    assert coverage.executed == 0
    assert "shodan" in coverage.not_performed_providers


def test_dimension_name_and_level_are_independent_fields():
    """
    Regression test for a real bug found during development: the
    empty-evidence branch previously put the dimension's NAME
    ('Security Risk') into the same field the populated branch used
    for the qualitative LEVEL ('LOW'/'CRITICAL'), producing
    inconsistent output depending on whether any evidence existed.
    """

    empty_result = assess([], expected_providers=["p1"])

    assert empty_result.security_risk.name == "Security Risk"
    assert empty_result.security_risk.level == "LOW"

    populated_result = assess(
        [_ev(provider="hibp", severity=95, confidence=95, source_reliability=0.9)],
        expected_providers=["hibp"],
    )

    assert populated_result.security_risk.name == "Security Risk"
    assert populated_result.security_risk.level == "CRITICAL"
