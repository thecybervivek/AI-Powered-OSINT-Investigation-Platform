from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.evidence_correlation import InvestigationRef
from backend.app.utils.evidence_correlation import find_shared_indicators
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

# How much an included investigation's own risk_score counts toward the
# composite, based on how completely it ran. A FAILED investigation's
# risk_score (if any) is not trustworthy evidence, so it contributes
# nothing rather than diluting the average toward zero.
_STATUS_WEIGHT = {
    InvestigationStatus.COMPLETED: 1.0,
    InvestigationStatus.PARTIAL: 0.7,
    InvestigationStatus.FAILED: 0.0,
    InvestigationStatus.RUNNING: 0.0,
    InvestigationStatus.QUEUED: 0.0,
}


class CompositeRiskService:
    """
    Orchestrates Milestone 9 Part 8 (Risk Engine Extension): combines
    the already-computed risk_score of several of the user's own past
    investigations (of any type, from any milestone) into one composite
    view. Runs no new external integrations of its own - every score it
    combines was already produced by that investigation's own module.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    def combine(
        self,
        *,
        user_id: str,
        investigation_ids: list[str],
        label: str,
    ) -> Investigation:

        composite = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.RISK_ASSESSMENT,
                target=label,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        included: list[Investigation] = []
        missing_ids: list[str] = []

        for investigation_id in investigation_ids:

            found = self.repository.get_owned(investigation_id, user_id)

            if found is None or found.id == composite.id:
                missing_ids.append(investigation_id)
                continue

            included.append(found)

        composite_score, confidence_score = self._compute_composite_score(included)

        evidence = find_shared_indicators(
            [
                InvestigationRef(
                    investigation_id=inv.id,
                    target=inv.target,
                    investigation_type=inv.investigation_type.value,
                )
                for inv in included
            ]
        )

        analysis_data = {
            "label": label,
            "requested_investigation_ids": investigation_ids,
            "included_investigations": [
                {
                    "investigation_id": inv.id,
                    "investigation_type": inv.investigation_type.value,
                    "target": inv.target,
                    "status": inv.status.value,
                    "risk_score": inv.risk_score,
                    "risk_level": inv.risk_level.value if inv.risk_level else None,
                }
                for inv in included
            ],
            "missing_or_not_owned_ids": missing_ids,
            "composite_risk_score": composite_score,
            "composite_risk_level": risk_level_from_score(composite_score).value,
            "confidence_score": confidence_score,
            "evidence_correlation": evidence,
        }

        self.repository.add_result(
            InvestigationResult(
                investigation_id=composite.id,
                source="composite_risk_analysis",
                status=(
                    ModuleResultStatus.SUCCESS
                    if included
                    else ModuleResultStatus.NOT_FOUND
                ),
                data=analysis_data,
                error_message=(
                    None
                    if included
                    else "None of the requested investigation_ids belong to this user."
                ),
            )
        )

        summary = self._build_summary(label, included, evidence)

        return self.repository.update(
            composite,
            status=(
                InvestigationStatus.COMPLETED
                if included
                else InvestigationStatus.FAILED
            ),
            risk_score=composite_score,
            risk_level=risk_level_from_score(composite_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------
    # Composite Risk Score / Composite Risk Level / Confidence Score
    # ------------------------------------------------------

    def _compute_composite_score(
        self,
        included: list[Investigation],
    ) -> tuple[float, float]:
        """
        Composite score: weighted average of each included
        investigation's own risk_score, weighted by how completely that
        investigation ran (see _STATUS_WEIGHT). Investigations with no
        risk_score at all (None) are excluded from the average
        entirely - they contribute no evidence either way, rather than
        silently counting as zero risk.

        Confidence score: how much this composite should be trusted -
        rises with (a) more investigations corroborating it and (b) a
        higher proportion of them having actually completed cleanly.
        """

        weighted_sum = 0.0
        total_weight = 0.0

        for inv in included:

            if inv.risk_score is None:
                continue

            weight = _STATUS_WEIGHT.get(inv.status, 0.0)

            weighted_sum += inv.risk_score * weight
            total_weight += weight

        weighted_average = clamp(weighted_sum / total_weight) if total_weight else 0.0
        # A confirmed severe observation must not be diluted by unrelated low-risk
        # observations. Preserve the strongest completed/partial signal as a floor.
        strongest = max(
            (inv.risk_score or 0.0 for inv in included if _STATUS_WEIGHT.get(inv.status, 0.0) > 0),
            default=0.0,
        )
        composite_score = max(weighted_average, strongest)

        if not included:
            return 0.0, 0.0

        # Completeness is about whether each investigation's own module
        # finished cleanly - evaluated independently of whether that
        # investigation happened to produce a numeric risk_score, so it
        # is NOT computed inside the risk_score-filtered loop above (an
        # earlier version of this method did exactly that, which
        # silently zeroed out confidence for cleanly-completed
        # investigations that simply had nothing to score).
        completed_count = sum(
            1 for inv in included if inv.status == InvestigationStatus.COMPLETED
        )

        completeness_ratio = completed_count / len(included)
        usable = sum(1 for inv in included if inv.risk_score is not None and _STATUS_WEIGHT.get(inv.status, 0.0) > 0)
        evidence_ratio = usable / len(included)
        confidence_score = clamp(completeness_ratio * 60 + evidence_ratio * 40)

        return round(composite_score, 2), round(confidence_score, 2)

    def _build_summary(
        self,
        label: str,
        included: list[Investigation],
        evidence: list[dict],
    ) -> str:

        if not included:
            return (
                f"Composite risk assessment '{label}' could not be built - "
                "none of the requested investigations belong to this user."
            )

        base = (
            f"Composite risk assessment '{label}' combines "
            f"{len(included)} investigation(s)."
        )

        if evidence:

            strongest = evidence[0]

            base += (
                f" {len(evidence)} shared-indicator correlation(s) found, "
                f"strongest: '{strongest['shared_indicator']}' referenced by "
                f"{strongest['investigation_count']} investigations."
            )

        return base
