from backend.app.core.intelligence.evidence import Evidence
from backend.app.core.intelligence.evidence import EvidenceState
from backend.app.core.intelligence.evidence import EvidenceType
from backend.app.core.intelligence.recommendations import build_recommendations
from backend.app.core.intelligence.recommendations import RecommendationCategory
from backend.app.core.intelligence.recommendations import RecommendationPriority


def _ev(**kw) -> Evidence:

    defaults = dict(
        indicator="x", investigation_id="inv1", provider="p",
        evidence_type=EvidenceType.BREACH_EXPOSURE, state=EvidenceState.SUCCESS,
        severity=50, confidence=80,
    )
    defaults.update(kw)

    return Evidence(**defaults)


def test_breach_exposure_produces_credential_remediation():

    recs = build_recommendations([_ev(severity=80)], coverage_gaps=[])

    assert len(recs) == 1
    assert recs[0].category == RecommendationCategory.CREDENTIAL_REMEDIATION
    assert recs[0].priority == RecommendationPriority.URGENT
    assert len(recs[0].supporting_evidence) == 1


def test_lower_severity_breach_is_high_not_urgent():

    recs = build_recommendations([_ev(severity=40)], coverage_gaps=[])

    assert recs[0].priority == RecommendationPriority.HIGH


def test_malicious_evidence_produces_containment_recommendation():

    recs = build_recommendations(
        [_ev(evidence_type=EvidenceType.SECURITY_MALICIOUS, severity=90)],
        coverage_gaps=[],
    )

    assert recs[0].category == RecommendationCategory.CONTAINMENT_INVESTIGATION
    assert recs[0].priority == RecommendationPriority.URGENT


def test_multiple_findings_of_same_type_grouped_into_one_recommendation():

    recs = build_recommendations(
        [_ev(severity=80, summary="f1"), _ev(severity=60, summary="f2")],
        coverage_gaps=[],
    )

    assert len(recs) == 1
    assert len(recs[0].supporting_evidence) == 2


def test_coverage_gaps_produce_their_own_recommendation():

    recs = build_recommendations([], coverage_gaps=["shodan did not execute", "censys did not execute"])

    assert len(recs) == 1
    assert recs[0].category == RecommendationCategory.COVERAGE_GAP
    assert "2 expected provider" in recs[0].rationale


def test_no_evidence_and_no_gaps_produces_no_recommendations():

    assert build_recommendations([], []) == []


def test_non_conclusive_evidence_never_triggers_a_recommendation():

    recs = build_recommendations([_ev(state=EvidenceState.FAILED, severity=90)], coverage_gaps=[])

    assert recs == []


def test_every_recommendation_traces_back_to_supporting_evidence():
    """Recommendations must be traceable to evidence - never fabricated without a source."""

    recs = build_recommendations([_ev(severity=80)], coverage_gaps=[])

    for rec in recs:
        if rec.category != RecommendationCategory.COVERAGE_GAP:
            assert len(rec.supporting_evidence) > 0
