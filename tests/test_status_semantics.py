from backend.app.core.intelligence.evidence import EvidenceState
from backend.app.core.intelligence.status_semantics import determine_status
from backend.app.core.intelligence.status_semantics import determine_status_from_evidence_states
from backend.app.core.intelligence.status_semantics import InvestigationStatusOutcome


def test_no_conclusive_evidence_is_failed():

    assert determine_status(conclusive_count=0, total_expected=5) == InvestigationStatusOutcome.FAILED
    assert determine_status(conclusive_count=0, total_expected=0) == InvestigationStatusOutcome.FAILED


def test_full_coverage_is_completed():

    assert determine_status(conclusive_count=5, total_expected=5) == InvestigationStatusOutcome.COMPLETED


def test_partial_coverage_is_partial():

    assert determine_status(conclusive_count=3, total_expected=5) == InvestigationStatusOutcome.PARTIAL


def test_one_provider_failure_does_not_fail_the_investigation():

    states = [EvidenceState.SUCCESS, EvidenceState.SUCCESS, EvidenceState.FAILED]

    assert determine_status_from_evidence_states(states) == InvestigationStatusOutcome.PARTIAL


def test_all_non_conclusive_states_is_failed():

    states = [EvidenceState.NOT_PERFORMED, EvidenceState.FAILED, EvidenceState.QUOTA_EXHAUSTED]

    assert determine_status_from_evidence_states(states) == InvestigationStatusOutcome.FAILED


def test_all_not_found_is_completed_not_failed():
    """A genuinely executed 'nothing found' result is a completed assessment, not a failure."""

    states = [EvidenceState.NOT_FOUND, EvidenceState.NOT_FOUND]

    assert determine_status_from_evidence_states(states) == InvestigationStatusOutcome.COMPLETED
