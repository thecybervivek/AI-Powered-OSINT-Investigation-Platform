from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.services.composite_risk_service import CompositeRiskService
from backend.app.utils.evidence_correlation import InvestigationRef
from backend.app.utils.evidence_correlation import find_shared_indicators
from backend.app.utils.evidence_correlation import normalize_indicator


# ==========================================================
# evidence_correlation.py
# ==========================================================

def test_normalize_indicator_extracts_email_domain():

    assert normalize_indicator("user@Example.COM") == "example.com"
    assert normalize_indicator("  example.com  ") == "example.com"


def test_find_shared_indicators_correlates_email_and_domain():

    refs = [
        InvestigationRef("inv1", "user@example.com", "email"),
        InvestigationRef("inv2", "example.com", "domain"),
        InvestigationRef("inv3", "unrelated.org", "domain"),
    ]

    result = find_shared_indicators(refs)

    assert len(result) == 1
    assert result[0]["shared_indicator"] == "example.com"
    assert result[0]["investigation_count"] == 2


def test_find_shared_indicators_three_way_correlation():

    refs = [
        InvestigationRef("inv1", "1.2.3.4", "ip_address"),
        InvestigationRef("inv2", "1.2.3.4", "threat_intelligence"),
        InvestigationRef("inv3", "1.2.3.4", "malware"),
    ]

    result = find_shared_indicators(refs)

    assert len(result) == 1
    assert result[0]["investigation_count"] == 3


def test_find_shared_indicators_no_correlation():

    refs = [
        InvestigationRef("inv1", "a.com", "domain"),
        InvestigationRef("inv2", "b.com", "domain"),
    ]

    assert find_shared_indicators(refs) == []


def test_find_shared_indicators_single_investigation_never_correlates():

    assert find_shared_indicators(
        [InvestigationRef("inv1", "solo.com", "domain")]
    ) == []


def test_find_shared_indicators_sorts_strongest_first():

    refs = [
        InvestigationRef("a", "x.com", "domain"),
        InvestigationRef("b", "x.com", "ip_address"),
        InvestigationRef("c", "y.com", "domain"),
        InvestigationRef("d", "y.com", "ip_address"),
        InvestigationRef("e", "y.com", "malware"),
    ]

    result = find_shared_indicators(refs)

    assert result[0]["shared_indicator"] == "y.com"
    assert result[0]["investigation_count"] == 3
    assert result[1]["investigation_count"] == 2


# ==========================================================
# CompositeRiskService - pure logic
# ==========================================================

def _service() -> CompositeRiskService:
    return CompositeRiskService(db=None)


def _investigation(
    risk_score,
    status: InvestigationStatus,
) -> Investigation:

    inv = Investigation(
        user_id="u1",
        investigation_type=InvestigationType.DOMAIN,
        target="example.com",
        status=status,
    )

    inv.risk_score = risk_score

    return inv


def test_composite_score_empty_list_returns_zero():

    service = _service()

    score, confidence = service._compute_composite_score([])

    assert score == 0.0
    assert confidence == 0.0


def test_composite_score_preserves_strongest_completed_signal():

    service = _service()

    included = [
        _investigation(80, InvestigationStatus.COMPLETED),
        _investigation(40, InvestigationStatus.COMPLETED),
    ]

    score, confidence = service._compute_composite_score(included)

    # Weighted average = 60, but the strongest valid signal (80)
    # acts as the composite floor so severe evidence is not diluted.
    assert score == 80.0

    # completeness_ratio = 2/2 = 1.0
    # evidence_ratio = 2/2 = 1.0
    # confidence = 1.0*60 + 1.0*40 = 100
    assert confidence == 100.0


def test_composite_score_excludes_none_risk_scores():

    service = _service()

    included = [
        _investigation(90, InvestigationStatus.COMPLETED),
        _investigation(None, InvestigationStatus.FAILED),
    ]

    score, confidence = service._compute_composite_score(included)

    # Only the completed 90-point investigation contributes risk.
    assert score == 90.0

    # completeness_ratio = 1/2 = 0.5
    # evidence_ratio = 1/2 = 0.5
    # confidence = 0.5*60 + 0.5*40 = 50
    assert confidence == 50.0


def test_composite_score_preserves_strongest_partial_signal():

    service = _service()

    included = [
        _investigation(20, InvestigationStatus.COMPLETED),
        _investigation(100, InvestigationStatus.PARTIAL),
    ]

    score, confidence = service._compute_composite_score(included)

    # Weighted average:
    # (20*1.0 + 100*0.7) / 1.7 = 52.94
    #
    # The 100-point PARTIAL result still has a non-zero status weight,
    # therefore it is usable evidence and acts as the severe-signal floor.
    assert score == 100.0

    # completeness_ratio = 1/2 = 0.5
    # evidence_ratio = 2/2 = 1.0
    # confidence = 0.5*60 + 1.0*40 = 70
    assert confidence == 70.0


def test_composite_score_zero_when_no_numeric_risk_evidence():

    service = _service()

    included = [
        _investigation(None, InvestigationStatus.COMPLETED),
        _investigation(None, InvestigationStatus.COMPLETED),
    ]

    score, confidence = service._compute_composite_score(included)

    # Both investigations completed, but neither produced numeric
    # risk evidence, so composite risk remains zero.
    assert score == 0.0

    # completeness_ratio = 2/2 = 1.0
    # evidence_ratio = 0/2 = 0.0
    # confidence = 1.0*60 + 0.0*40 = 60
    assert confidence == 60.0


def test_critical_signal_is_not_diluted_by_low_risk_findings():

    service = _service()

    investigations = [
        _investigation(95, InvestigationStatus.COMPLETED),
        _investigation(5, InvestigationStatus.COMPLETED),
        _investigation(5, InvestigationStatus.COMPLETED),
        _investigation(5, InvestigationStatus.COMPLETED),
    ]

    score, confidence = service._compute_composite_score(investigations)

    # A confirmed critical observation must survive aggregation.
    assert score == 95.0
    assert confidence == 100.0


def test_failed_investigation_does_not_raise_composite_risk():

    service = _service()

    investigations = [
        _investigation(30, InvestigationStatus.COMPLETED),
        _investigation(100, InvestigationStatus.FAILED),
    ]

    score, confidence = service._compute_composite_score(investigations)

    # FAILED has status weight 0.0 and therefore cannot become
    # the strongest usable signal.
    assert score == 30.0

    # completeness_ratio = 1/2
    # evidence_ratio = 1/2 because FAILED risk is unusable
    assert confidence == 50.0