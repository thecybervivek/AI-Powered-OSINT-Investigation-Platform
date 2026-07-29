"""
Explainable Risk / Exposure / Confidence / Coverage scoring.

Replaces naive-average composite scoring with an explainable model that
cannot let a single critical signal wash out into an average, and that
treats "how much evidence exists and how independent is it" as a first-
class dimension (Confidence/Coverage) rather than folding it silently
into the risk number.

Deliberately depends only on backend.app.core.intelligence.evidence -
no SQLAlchemy, no httpx, so it's fully unit-testable without a
database or network, and any module can feed it Evidence objects
without this engine knowing anything about that module's provider
wire format.
"""

from dataclasses import dataclass
from dataclasses import field

from backend.app.core.intelligence.evidence import Evidence
from backend.app.core.intelligence.evidence import EvidenceState
from backend.app.core.intelligence.evidence import EvidenceType

# Evidence types that represent actual security/malicious signal vs.
# ones that represent exposure/hygiene/reputation instead. A finding
# can only push ONE of Security Risk or Exposure, never both, so a
# large public footprint doesn't also get double-counted as "risk".
_SECURITY_RISK_TYPES = frozenset(
    {
        EvidenceType.SECURITY_MALICIOUS,
        EvidenceType.SECURITY_SUSPICIOUS,
        EvidenceType.BREACH_EXPOSURE,
        EvidenceType.REPUTATION_SIGNAL,
    }
)

_EXPOSURE_TYPES = frozenset(
    {
        EvidenceType.PUBLIC_PRESENCE,
        EvidenceType.INFRASTRUCTURE_FACT,
        EvidenceType.PRIVACY_EXPOSURE,
        EvidenceType.HYGIENE_GAP,
    }
)


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


@dataclass(frozen=True)
class ScoreDimension:
    """One of the four independent dimensions - never call this 'the' risk score."""

    value: float
    name: str
    level: str
    drivers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": round(self.value, 2),
            "name": self.name,
            "level": self.level,
            "drivers": self.drivers,
        }


def _level_label(score: float) -> str:

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


@dataclass(frozen=True)
class Finding:
    """
    One scored, deduplicated piece of evidence, after independence/
    diversity weighting has been applied - what actually feeds the
    composite dimension scores below.
    """

    evidence: Evidence
    strength: float  # 0-100, already adjusted for reliability/confidence/freshness/independence


def _finding_strength(evidence: Evidence, independence_weight: float) -> float:
    """
    strength = severity x reliability x confidence x freshness x independence

    Every factor except severity is expressed 0-1 so it can only ever
    REDUCE severity, never inflate it above what the evidence itself
    claims - this is what stops five weak, correlated observations
    from ever outscoring one strong, well-corroborated one, while still
    never letting corroboration invent severity that wasn't there.
    """

    if not evidence.state.is_conclusive:
        return 0.0

    confidence_factor = _clamp(evidence.confidence, 0, 100) / 100
    reliability_factor = _clamp(evidence.source_reliability, 0, 1)
    freshness_factor = _clamp(evidence.freshness, 0, 1)

    return (
        evidence.severity
        * reliability_factor
        * confidence_factor
        * freshness_factor
        * independence_weight
    )


def _deduplicate(evidence_list: list[Evidence]) -> list[Evidence]:
    """
    Drops exact duplicate observations (same provider + same evidence
    type + same summary) - a provider that returns the same finding
    twice within one investigation must not count twice.
    """

    seen: set[tuple[str, str, str]] = set()
    deduped: list[Evidence] = []

    for ev in evidence_list:

        key = (ev.provider, ev.evidence_type.value, ev.summary)

        if key in seen:
            continue

        seen.add(key)
        deduped.append(ev)

    return deduped


def _independence_weights(evidence_list: list[Evidence]) -> dict[int, float]:
    """
    Assigns each piece of evidence a 0-1 independence weight based on
    how many OTHER observations share its provider - repeated
    observations from the very same provider are corroboration of a
    much weaker kind than independent providers agreeing, so each
    additional same-provider observation is worth progressively less
    (capped, never reaching zero, and never inflating past the first
    observation's full weight of 1.0).
    """

    provider_counts: dict[str, int] = {}

    for ev in evidence_list:
        provider_counts[ev.provider] = provider_counts.get(ev.provider, 0) + 1

    provider_seen: dict[str, int] = {}
    weights: dict[int, float] = {}

    for index, ev in enumerate(evidence_list):

        seen_so_far = provider_seen.get(ev.provider, 0)
        provider_seen[ev.provider] = seen_so_far + 1

        # First observation from a provider: full weight. Each
        # subsequent one from the SAME provider: diminishing (but
        # never zero) additional weight - capped so a single noisy
        # provider can never single-handedly dominate the score.
        weights[index] = 1.0 if seen_so_far == 0 else _clamp(0.5 / (seen_so_far + 1), 0.05, 0.5)

    return weights


def _build_findings(evidence_list: list[Evidence]) -> list[Finding]:

    deduped = _deduplicate(evidence_list)
    weights = _independence_weights(deduped)

    return [
        Finding(evidence=ev, strength=_finding_strength(ev, weights[i]))
        for i, ev in enumerate(deduped)
    ]


def _aggregate_dimension(
    findings: list[Finding],
    types: frozenset,
    dimension_name: str,
) -> ScoreDimension:
    """
    Critical-signal-preserving aggregation: the dimension score is the
    STRONGEST single finding, with weaker corroborating findings
    contributing a small additional bump (capped) rather than being
    averaged in - a single confirmed-malicious hash (severity ~95)
    cannot be diluted toward "medium" by four unrelated low-severity
    observations the way a naive average would.
    """

    relevant = sorted(
        (f for f in findings if f.evidence.evidence_type in types),
        key=lambda f: f.strength,
        reverse=True,
    )

    if not relevant:
        return ScoreDimension(value=0.0, name=dimension_name, level=_level_label(0.0), drivers=[])

    top = relevant[0]
    corroboration_bump = sum(f.strength for f in relevant[1:]) * 0.15
    corroboration_bump = _clamp(corroboration_bump, 0, 100 - top.strength)

    score = _clamp(top.strength + corroboration_bump)

    drivers = [
        f.evidence.summary or f"{f.evidence.provider}: {f.evidence.evidence_type.value}"
        for f in relevant[:5]
    ]

    return ScoreDimension(value=score, name=dimension_name, level=_level_label(score), drivers=drivers)


@dataclass(frozen=True)
class CoverageResult:

    executed: int
    expected: int
    percentage: float
    not_performed_providers: list[str]

    def to_dict(self) -> dict:
        return {
            "executed": self.executed,
            "expected": self.expected,
            "percentage": round(self.percentage, 1),
            "not_performed_providers": self.not_performed_providers,
        }


def compute_coverage(evidence_list: list[Evidence], expected_providers: list[str]) -> CoverageResult:
    """
    Coverage = how much of the EXPECTED/configured assessment actually
    executed, regardless of what it found. 5 expected providers with 3
    SUCCESS + 1 FAILED + 1 NOT_PERFORMED is 60% coverage, full stop -
    FAILED and NOT_PERFORMED both count against coverage even though
    they're different reasons (see evidence.py's EvidenceState).
    """

    executed_providers = {
        ev.provider for ev in evidence_list if ev.state.is_conclusive
    }

    not_performed = sorted(set(expected_providers) - executed_providers)

    executed = len(executed_providers & set(expected_providers))
    expected = len(expected_providers) if expected_providers else len(executed_providers)

    percentage = (executed / expected * 100) if expected else 0.0

    return CoverageResult(
        executed=executed,
        expected=expected,
        percentage=percentage,
        not_performed_providers=not_performed,
    )


def compute_confidence(evidence_list: list[Evidence], coverage: CoverageResult) -> ScoreDimension:
    """
    Confidence = how much the available evidence should be trusted -
    driven by corroboration diversity (distinct providers agreeing),
    average freshness/reliability of what was gathered, AND coverage
    (thin coverage caps confidence even if what little was gathered
    looks clean - this is what stops "0 providers executed" from ever
    producing a high-confidence benign verdict).
    """

    conclusive = [ev for ev in evidence_list if ev.state.is_conclusive]

    if not conclusive:
        return ScoreDimension(
            value=0.0, name="Confidence", level=_level_label(0.0),
            drivers=["No conclusive evidence gathered"],
        )

    distinct_providers = {ev.provider for ev in conclusive}
    diversity_factor = _clamp(len(distinct_providers) / max(len(conclusive), 1), 0, 1)

    avg_reliability = sum(ev.source_reliability for ev in conclusive) / len(conclusive)
    avg_freshness = sum(ev.freshness for ev in conclusive) / len(conclusive)

    base_confidence = (
        (0.4 * diversity_factor + 0.3 * avg_reliability + 0.3 * avg_freshness) * 100
    )

    # Coverage acts as a hard cap, not just an input - confidence can
    # never exceed what fraction of the intended assessment actually ran.
    coverage_capped = min(base_confidence, coverage.percentage + 15)

    score = _clamp(coverage_capped)

    drivers = [
        f"{len(distinct_providers)} distinct provider(s) corroborating",
        f"coverage {coverage.percentage:.0f}%",
    ]

    return ScoreDimension(value=score, name="Confidence", level=_level_label(score), drivers=drivers)


@dataclass(frozen=True)
class CompositeAssessment:

    security_risk: ScoreDimension
    exposure: ScoreDimension
    confidence: ScoreDimension
    coverage: CoverageResult
    critical_evidence: list[Evidence]
    coverage_gaps: list[str]

    def to_dict(self) -> dict:
        return {
            "security_risk": self.security_risk.to_dict(),
            "exposure": self.exposure.to_dict(),
            "confidence": self.confidence.to_dict(),
            "coverage": self.coverage.to_dict(),
            "critical_evidence": [e.to_dict() for e in self.critical_evidence],
            "coverage_gaps": self.coverage_gaps,
        }


def assess(
    evidence_list: list[Evidence],
    expected_providers: list[str],
) -> CompositeAssessment:
    """
    Single entry point: turns a flat list of Evidence + the set of
    providers that WERE expected to run into the four independent
    dimensions plus explainability (critical evidence, coverage gaps).
    """

    findings = _build_findings(evidence_list)

    security_risk = _aggregate_dimension(findings, _SECURITY_RISK_TYPES, "Security Risk")
    exposure = _aggregate_dimension(findings, _EXPOSURE_TYPES, "Digital Exposure")
    coverage = compute_coverage(evidence_list, expected_providers)
    confidence = compute_confidence(evidence_list, coverage)

    critical_evidence = [
        f.evidence
        for f in findings
        if f.strength >= 75 and f.evidence.evidence_type in _SECURITY_RISK_TYPES
    ]

    coverage_gaps = [
        f"{provider} did not execute"
        for provider in coverage.not_performed_providers
    ]

    return CompositeAssessment(
        security_risk=security_risk,
        exposure=exposure,
        confidence=confidence,
        coverage=coverage,
        critical_evidence=critical_evidence,
        coverage_gaps=coverage_gaps,
    )
