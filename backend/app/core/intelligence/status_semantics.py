"""
Centralized investigation status semantics (Section 10).

Every existing service in this codebase (username/email/domain/ip/url/
phone/breach/threat_intelligence/malware/dns_intelligence/...) hand-
rolls its own near-identical `_overall_status()` method. That
duplication is exactly how "one provider failure = investigation
failure" bugs creep in independently per module. This module is the
single definition; existing services can switch to calling
`determine_status()` instead of their own copy at their own pace (see
composite_risk_service.py in this delivery for the one worked example)
without every module needing to change in the same pass.

Definitions (must stay consistent with these three exact rules
throughout the codebase):

COMPLETED: sufficient intended assessment completed - not necessarily
           every provider, but enough conclusive evidence exists.
PARTIAL:   usable assessment exists, but meaningful coverage gaps
           remain (some expected providers did not produce conclusive
           evidence).
FAILED:    no usable assessment could be produced at all - every
           expected provider was NOT_PERFORMED/FAILED/RATE_LIMITED/
           QUOTA_EXHAUSTED/UNKNOWN; there is nothing to show.

A single provider failing does NOT automatically fail the whole
investigation - only the total absence of conclusive evidence does.
"""

from enum import Enum


class InvestigationStatusOutcome(str, Enum):

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


def determine_status(
    *,
    conclusive_count: int,
    total_expected: int,
) -> InvestigationStatusOutcome:
    """
    `conclusive_count`: how many expected providers produced a
    conclusive observation (EvidenceState.is_conclusive - SUCCESS or
    NOT_FOUND; see evidence.py). `total_expected`: how many providers
    were expected to run for this investigation.

    No conclusive evidence at all -> FAILED, regardless of how many
    providers were merely SKIPPED/NOT_PERFORMED (a provider correctly
    declining because it wasn't configured is not itself a failure -
    but if EVERY provider ends up non-conclusive, there is genuinely
    nothing to show, which is what FAILED means here).
    """

    if total_expected <= 0:
        # Nothing was ever expected to run - can't meaningfully call
        # this COMPLETED or PARTIAL; treat as FAILED (no assessment).
        return InvestigationStatusOutcome.FAILED

    if conclusive_count <= 0:
        return InvestigationStatusOutcome.FAILED

    if conclusive_count >= total_expected:
        return InvestigationStatusOutcome.COMPLETED

    return InvestigationStatusOutcome.PARTIAL


def determine_status_from_evidence_states(states: list) -> InvestigationStatusOutcome:
    """
    Convenience wrapper: takes a list of objects/strings exposing
    `.is_conclusive` (EvidenceState members) or plain conclusive
    booleans, and derives conclusive_count/total_expected directly -
    the common case where callers already have a flat list of per-
    provider EvidenceState values for this investigation.
    """

    total_expected = len(states)
    conclusive_count = sum(
        1 for s in states if getattr(s, "is_conclusive", bool(s))
    )

    return determine_status(conclusive_count=conclusive_count, total_expected=total_expected)
