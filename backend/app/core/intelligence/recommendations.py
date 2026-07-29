"""
Recommendation input model (Section 11).

Account 3 owns rendering recommendations in the UI; this module owns
the evidence-driven INPUT to that rendering - a Recommendation is
useless as an audit trail if it can't be traced back to the specific
Evidence that produced it, so `supporting_evidence` is mandatory, never
an afterthought field.
"""

from dataclasses import dataclass
from dataclasses import field
from enum import Enum

from backend.app.core.intelligence.evidence import Evidence
from backend.app.core.intelligence.evidence import EvidenceType


class RecommendationCategory(str, Enum):

    CREDENTIAL_REMEDIATION = "credential_remediation"
    CONTAINMENT_INVESTIGATION = "containment_investigation"
    PRIVACY_REVIEW = "privacy_review"
    COVERAGE_GAP = "coverage_gap"
    HYGIENE_IMPROVEMENT = "hygiene_improvement"


class RecommendationPriority(str, Enum):

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


@dataclass(frozen=True)
class Recommendation:

    category: RecommendationCategory
    priority: RecommendationPriority
    action: str
    rationale: str
    supporting_evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:

        return {
            "category": self.category.value,
            "priority": self.priority.value,
            "action": self.action,
            "rationale": self.rationale,
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
        }


def build_recommendations(
    evidence_list: list[Evidence],
    coverage_gaps: list[str],
) -> list[Recommendation]:
    """
    Derives recommendations purely from the evidence already gathered
    (never triggers new provider calls). Grouped by evidence_type so
    multiple breach findings, for example, produce ONE credential-
    remediation recommendation citing all of them, not one per finding.
    """

    recommendations: list[Recommendation] = []

    breach_evidence = [
        e for e in evidence_list
        if e.evidence_type == EvidenceType.BREACH_EXPOSURE and e.state.is_conclusive and e.severity > 0
    ]

    if breach_evidence:

        recommendations.append(
            Recommendation(
                category=RecommendationCategory.CREDENTIAL_REMEDIATION,
                priority=RecommendationPriority.URGENT if any(e.severity >= 70 for e in breach_evidence) else RecommendationPriority.HIGH,
                action="Rotate passwords and enable multi-factor authentication for the affected account(s).",
                rationale="Credential/data breach exposure was found for this indicator.",
                supporting_evidence=breach_evidence,
            )
        )

    malicious_evidence = [
        e for e in evidence_list
        if e.evidence_type == EvidenceType.SECURITY_MALICIOUS and e.state.is_conclusive and e.severity > 0
    ]

    if malicious_evidence:

        recommendations.append(
            Recommendation(
                category=RecommendationCategory.CONTAINMENT_INVESTIGATION,
                priority=RecommendationPriority.URGENT,
                action="Isolate/contain the affected indicator and search your environment for related IOCs.",
                rationale="One or more providers confirmed malicious activity associated with this indicator.",
                supporting_evidence=malicious_evidence,
            )
        )

    privacy_evidence = [
        e for e in evidence_list
        if e.evidence_type == EvidenceType.PRIVACY_EXPOSURE and e.state.is_conclusive and e.severity > 0
    ]

    if privacy_evidence:

        recommendations.append(
            Recommendation(
                category=RecommendationCategory.PRIVACY_REVIEW,
                priority=RecommendationPriority.MEDIUM,
                action="Review and strip embedded location/personal metadata before sharing this file publicly.",
                rationale="GPS or other personally-identifying metadata was found embedded in file content.",
                supporting_evidence=privacy_evidence,
            )
        )

    hygiene_evidence = [
        e for e in evidence_list
        if e.evidence_type == EvidenceType.HYGIENE_GAP and e.state.is_conclusive and e.severity > 0
    ]

    if hygiene_evidence:

        recommendations.append(
            Recommendation(
                category=RecommendationCategory.HYGIENE_IMPROVEMENT,
                priority=RecommendationPriority.MEDIUM,
                action="Address the identified configuration gap (e.g. missing/weak SPF or DMARC, expired TLS certificate).",
                rationale="One or more infrastructure hygiene gaps were identified.",
                supporting_evidence=hygiene_evidence,
            )
        )

    if coverage_gaps:

        recommendations.append(
            Recommendation(
                category=RecommendationCategory.COVERAGE_GAP,
                priority=RecommendationPriority.LOW,
                action="Configure the missing provider API key(s) or retry once available, then re-run this investigation.",
                rationale=f"{len(coverage_gaps)} expected provider(s) did not execute: " + "; ".join(coverage_gaps),
            )
        )

    return recommendations
