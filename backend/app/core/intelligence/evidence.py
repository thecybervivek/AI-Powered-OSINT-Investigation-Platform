"""
Normalized Evidence Model.

The core anti-pattern this replaces: treating a provider's raw
execution outcome as if it were already a security verdict. A 0 risk
score, a NOT_FOUND result, a SKIPPED provider, and an inconclusive
result are all completely different situations that a flat status
model doesn't distinguish - it has no state for "we never even tried"
versus "we tried and found nothing" versus "the provider's own answer
was inconclusive".

EvidenceState is intentionally a superset, kept independent of
ModuleResultStatus so this module doesn't force every existing
provider file to change - `from_module_result_status()` below adapts
the existing status into this richer vocabulary, so callers written
against the old status keep working while new/updated code can start
speaking EvidenceState directly.
"""

from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from enum import Enum
from typing import Any


class EvidenceState(str, Enum):
    """
    What actually happened when a provider was asked about an
    indicator - execution semantics, not a verdict. Never collapse this
    to a boolean "found something bad" - see evidence_type/severity on
    Evidence itself for that.

    PARTIAL/UNABLE_TO_VERIFY/NO_DATA were split out from a single
    generic UNKNOWN (audit finding: collapsing them lost real
    investigation semantics a reader legitimately needs - "this
    provider's own result was incomplete" (PARTIAL) is a materially
    different situation from "the provider ran but had nothing at all"
    (NO_DATA), which is different again from "the provider couldn't
    reach a conclusion" (UNABLE_TO_VERIFY), even though none of the
    three is conclusive). UNKNOWN is kept for the true fallback case -
    a status value this module has never seen - not reused as a
    catch-all for named, understood non-conclusive outcomes.
    """

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    PARTIAL = "partial"
    UNABLE_TO_VERIFY = "unable_to_verify"
    NO_DATA = "no_data"
    NOT_PERFORMED = "not_performed"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXHAUSTED = "quota_exhausted"
    UNKNOWN = "unknown"

    @property
    def is_conclusive(self) -> bool:
        """
        True when this state represents an actual completed
        observation (whether or not anything was found) - false for
        every state where the platform simply doesn't have an answer.
        This is the single check that stops "no answer" from silently
        becoming "safe": PARTIAL/UNABLE_TO_VERIFY/NO_DATA/
        NOT_PERFORMED/FAILED/RATE_LIMITED/QUOTA_EXHAUSTED/UNKNOWN are
        all is_conclusive=False.
        """

        return self in (EvidenceState.SUCCESS, EvidenceState.NOT_FOUND)

    @property
    def counts_as_benign_signal(self) -> bool:
        """
        True ONLY for a genuine, executed "we looked and found
        nothing" - NOT_FOUND. Every other state - including SUCCESS
        with no findings attached, which callers should represent as
        NOT_FOUND rather than an empty SUCCESS - must never be read as
        evidence of safety on its own. In particular, PARTIAL/
        UNABLE_TO_VERIFY/NO_DATA are attempted-but-inconclusive and
        must never be treated as benign just because they aren't an
        outright FAILED.
        """

        return self == EvidenceState.NOT_FOUND


def from_module_result_status(status: Any, *, is_configured: bool = True) -> EvidenceState:
    """
    Adapts the existing backend.app.models.investigation.ModuleResultStatus
    (SUCCESS/FOUND/NOT_FOUND/PARTIAL/UNABLE_TO_VERIFY/NO_DATA/
    RATE_LIMITED/FAILED/SKIPPED) into EvidenceState, so existing
    integrations/services can be wrapped without rewriting them. Takes
    the enum's `.value` string rather than importing the model module
    directly, so this file has zero dependency on SQLAlchemy or the
    rest of the app - callers pass whichever status object they have
    (or a plain string) and only its `.value`/str form is inspected.
    """

    raw = getattr(status, "value", status)
    raw = str(raw).lower()

    if raw in ("success", "found"):
        # FOUND is a SUCCESS that positively confirmed something - both
        # are conclusive, completed observations.
        return EvidenceState.SUCCESS

    if raw == "not_found":
        return EvidenceState.NOT_FOUND

    if raw == "failed":
        return EvidenceState.FAILED

    if raw == "rate_limited":
        return EvidenceState.RATE_LIMITED

    if raw == "partial":
        # Attempted (unlike SKIPPED/NOT_PERFORMED); the provider's own
        # result was incomplete - kept distinct from UNABLE_TO_VERIFY/
        # NO_DATA (audit finding: collapsing these into one generic
        # UNKNOWN loses real investigation semantics). Still never a
        # benign signal - only NOT_FOUND is.
        return EvidenceState.PARTIAL

    if raw == "unable_to_verify":
        # Attempted, but the provider couldn't reach any conclusion at
        # all (as opposed to PARTIAL's "reached an incomplete one").
        return EvidenceState.UNABLE_TO_VERIFY

    if raw == "no_data":
        # Attempted successfully, but the upstream source simply has no
        # data for this indicator - distinct from NOT_FOUND, which
        # asserts a confirmed negative.
        return EvidenceState.NO_DATA

    if raw == "skipped":
        # A provider reporting SKIPPED because it lacks an API key is
        # "we never tried"; some legacy callers overload SKIPPED for
        # "target type doesn't apply here" too - same semantic either
        # way, so both map to NOT_PERFORMED. `is_configured` is kept in
        # the signature for callers who want to log the distinction
        # even though it doesn't change the resulting EvidenceState.
        return EvidenceState.NOT_PERFORMED

    return EvidenceState.UNKNOWN


class EvidenceType(str, Enum):
    """
    What KIND of observation this is - orthogonal to EvidenceState.
    Used by the scoring engine to weight severity and by the
    correlation engine to classify relationships (identity/
    infrastructure/threat).
    """

    SECURITY_MALICIOUS = "security_malicious"       # confirmed malicious verdict
    SECURITY_SUSPICIOUS = "security_suspicious"      # suspicious but not confirmed
    BREACH_EXPOSURE = "breach_exposure"              # credential/data breach
    PUBLIC_PRESENCE = "public_presence"              # profile/account/discoverability
    INFRASTRUCTURE_FACT = "infrastructure_fact"      # DNS/WHOIS/ASN/cert facts
    PRIVACY_EXPOSURE = "privacy_exposure"             # GPS/PII in metadata
    HYGIENE_GAP = "hygiene_gap"                       # missing SPF/DMARC/expired cert
    REPUTATION_SIGNAL = "reputation_signal"           # community/vendor reputation score
    CORRELATION = "correlation"                       # cross-indicator relationship


@dataclass(frozen=True)
class Evidence:
    """
    One normalized, provider-agnostic observation. Every field the spec
    calls out is represented explicitly rather than left inside an
    opaque provider-specific payload - `raw_reference` is where that
    provider-specific payload still lives, but scoring/correlation code
    should never need to reach into it.
    """

    indicator: str
    investigation_id: str
    provider: str
    evidence_type: EvidenceType
    state: EvidenceState

    # 0-100: how strong/severe THIS finding is on its own terms (a
    # confirmed-malicious hash might be severity=95; a single public
    # GitHub profile might be severity=10). Only meaningful when
    # state.is_conclusive - callers should use severity=0 (not None)
    # for a NOT_FOUND, since "no severity" and "zero severity" ARE the
    # same thing for a genuine negative result specifically.
    severity: float = 0.0

    # 0-100: how much THIS specific observation should be trusted -
    # independent of state. A well-established provider's SUCCESS is
    # higher confidence than one from a provider with a history of
    # false positives; see source_reliability below for a lever on
    # this, and confidence itself for the value actually used.
    confidence: float = 50.0

    observed_at: datetime | None = None

    # 0-1: how reliable this PROVIDER is treated as, independent of any
    # single observation. Feeds the corroboration-independence
    # calculation in scoring.py so five same-provider observations
    # don't count as five independent sources.
    source_reliability: float = 0.7

    # How fresh this observation is, 0 (stale/unknown age) to 1 (just
    # observed). Scoring multiplies confidence by this.
    freshness: float = 1.0

    summary: str = ""
    raw_reference: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:

        return {
            "indicator": self.indicator,
            "investigation_id": self.investigation_id,
            "provider": self.provider,
            "evidence_type": self.evidence_type.value,
            "state": self.state.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "source_reliability": self.source_reliability,
            "freshness": self.freshness,
            "summary": self.summary,
        }
