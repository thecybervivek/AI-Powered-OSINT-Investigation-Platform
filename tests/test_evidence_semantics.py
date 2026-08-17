from backend.app.core.intelligence.evidence import Evidence
from backend.app.core.intelligence.evidence import EvidenceState
from backend.app.core.intelligence.evidence import EvidenceType
from backend.app.core.intelligence.evidence import from_module_result_status


class _FakeStatus:
    def __init__(self, value):
        self.value = value


def test_success_and_not_found_are_conclusive():

    assert EvidenceState.SUCCESS.is_conclusive is True
    assert EvidenceState.NOT_FOUND.is_conclusive is True


def test_not_performed_failed_rate_limited_quota_unknown_are_not_conclusive():

    for state in (
        EvidenceState.NOT_PERFORMED,
        EvidenceState.FAILED,
        EvidenceState.RATE_LIMITED,
        EvidenceState.QUOTA_EXHAUSTED,
        EvidenceState.UNKNOWN,
    ):
        assert state.is_conclusive is False, state


def test_not_found_is_the_only_benign_signal():
    """NOT_FOUND != unrelated states; only NOT_FOUND counts as benign."""

    assert EvidenceState.NOT_FOUND.counts_as_benign_signal is True

    for state in (
        EvidenceState.SUCCESS,
        EvidenceState.NOT_PERFORMED,
        EvidenceState.FAILED,
        EvidenceState.RATE_LIMITED,
        EvidenceState.QUOTA_EXHAUSTED,
        EvidenceState.UNKNOWN,
    ):
        assert state.counts_as_benign_signal is False, state


def test_failed_is_not_not_found():

    assert EvidenceState.FAILED != EvidenceState.NOT_FOUND
    assert EvidenceState.FAILED.counts_as_benign_signal != EvidenceState.NOT_FOUND.counts_as_benign_signal


def test_not_performed_never_contributes_benign_evidence():

    assert EvidenceState.NOT_PERFORMED.counts_as_benign_signal is False
    assert EvidenceState.NOT_PERFORMED.is_conclusive is False


def test_quota_exhausted_represented_distinctly():
    """QUOTA_EXHAUSTED must never be confused with NOT_FOUND or generic FAILED."""

    assert EvidenceState.QUOTA_EXHAUSTED != EvidenceState.NOT_FOUND
    assert EvidenceState.QUOTA_EXHAUSTED != EvidenceState.FAILED
    assert EvidenceState.QUOTA_EXHAUSTED.is_conclusive is False


def test_from_module_result_status_adapter():

    assert from_module_result_status(_FakeStatus("success")) == EvidenceState.SUCCESS
    assert from_module_result_status(_FakeStatus("not_found")) == EvidenceState.NOT_FOUND
    assert from_module_result_status(_FakeStatus("failed")) == EvidenceState.FAILED
    assert from_module_result_status(_FakeStatus("rate_limited")) == EvidenceState.RATE_LIMITED
    assert from_module_result_status(_FakeStatus("skipped")) == EvidenceState.NOT_PERFORMED
    assert from_module_result_status("success") == EvidenceState.SUCCESS
    assert from_module_result_status("something_new") == EvidenceState.UNKNOWN


def test_from_module_result_status_adapter_covers_new_provider_states():
    """
    FOUND/PARTIAL/UNABLE_TO_VERIFY/NO_DATA were added to
    ModuleResultStatus for the provider status model upgrade (spec
    section 7). FOUND is conclusive (like SUCCESS); the other three
    were attempted but inconclusive, so none of them may be read as a
    benign signal - only NOT_FOUND ever is. Each keeps its own distinct
    EvidenceState (audit finding: collapsing them into one generic
    UNKNOWN lost real investigation semantics) rather than merging into
    a single bucket.
    """

    assert from_module_result_status(_FakeStatus("found")) == EvidenceState.SUCCESS

    expected = {
        "partial": EvidenceState.PARTIAL,
        "unable_to_verify": EvidenceState.UNABLE_TO_VERIFY,
        "no_data": EvidenceState.NO_DATA,
    }

    for value, evidence_state in expected.items():
        state = from_module_result_status(_FakeStatus(value))
        assert state == evidence_state, value
        assert state.is_conclusive is False, value
        assert state.counts_as_benign_signal is False, value

    # And they must be distinguishable from each other and from a
    # genuinely-unrecognized status - not silently merged back together.
    assert len({EvidenceState.PARTIAL, EvidenceState.UNABLE_TO_VERIFY, EvidenceState.NO_DATA, EvidenceState.UNKNOWN}) == 4
    assert from_module_result_status(_FakeStatus("totally_unrecognized_status")) == EvidenceState.UNKNOWN


def test_evidence_to_dict_shape():

    ev = Evidence(
        indicator="1.2.3.4",
        investigation_id="inv1",
        provider="abuseipdb",
        evidence_type=EvidenceType.SECURITY_MALICIOUS,
        state=EvidenceState.SUCCESS,
        severity=90,
        confidence=85,
        source_reliability=0.8,
    )
    d = ev.to_dict()

    assert d["evidence_type"] == "security_malicious"
    assert d["state"] == "success"
    assert d["severity"] == 90
