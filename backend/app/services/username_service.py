import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.username import MaigretIntegration
from backend.app.integrations.username import SherlockIntegration
from backend.app.integrations.username import WhatsMyNameIntegration
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

_ENGINES = [
    SherlockIntegration(),
    MaigretIntegration(),
    WhatsMyNameIntegration(),
]


class UsernameIntelligenceService:
    """
    Orchestrates Milestone 2 (Username Intelligence): runs every engine
    concurrently against the target username, builds a unified
    cross-engine profile-existence view, computes confidence/risk
    scores, and persists everything into the Investigation tables.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        username: str,
    ) -> Investigation:

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.USERNAME,
                target=username,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        engine_results: list[IntegrationResult] = await asyncio.gather(
            *(engine.run(username) for engine in _ENGINES)
        )

        for engine_result in engine_results:

            self.repository.add_result(
                InvestigationResult(
                    investigation_id=investigation.id,
                    source=engine_result.source,
                    status=engine_result.status,
                    data=engine_result.data,
                    latency_ms=engine_result.latency_ms,
                    error_message=engine_result.error_message,
                )
            )

        unified = self._build_unified_profile(username, engine_results)

        overall_status = self._overall_status(engine_results)

        risk_score = self._compute_risk_score(unified)

        summary = (
            f"Found {unified['total_platforms_found']} matching profile(s) "
            f"across {unified['engines_run']} engine(s) for username "
            f"'{username}'."
        )

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------
    # Unified Cross-Engine Result
    # ------------------------------------------------------

    def _build_unified_profile(
        self,
        username: str,
        engine_results: list[IntegrationResult],
    ) -> dict:
        """
        Merges per-platform findings across all three engines into one
        deduplicated view, with a confidence score per platform based on
        how many engines agree it exists.
        """

        by_platform: dict[str, dict] = {}
        engines_run = 0

        for engine_result in engine_results:

            if engine_result.status == ModuleResultStatus.SKIPPED:
                continue

            engines_run += 1
            platform_rows = (engine_result.data or {}).get("results", [])

            for row in platform_rows:

                platform = row["platform"]
                entry = by_platform.setdefault(
                    platform,
                    {
                        "platform": platform,
                        "category": row.get("category"),
                        "profile_url": row.get("profile_url"),
                        "votes_exists": 0,
                        "votes_not_found": 0,
                        "votes_inconclusive": 0,
                        "sources": [],
                    },
                )

                entry["sources"].append(engine_result.source)

                if row.get("exists") is True:
                    entry["votes_exists"] += 1

                elif row.get("exists") is False:
                    entry["votes_not_found"] += 1

                else:
                    entry["votes_inconclusive"] += 1

        platforms = []

        for entry in by_platform.values():

            total_votes = (
                entry["votes_exists"]
                + entry["votes_not_found"]
                + entry["votes_inconclusive"]
            )

            confidence = (
                round(entry["votes_exists"] / total_votes * 100, 2)
                if total_votes
                else 0.0
            )

            platforms.append(
                {
                    **entry,
                    "confidence_score": confidence,
                    "confirmed": entry["votes_exists"] > 0,
                }
            )

        confirmed_platforms = [p for p in platforms if p["confirmed"]]

        return {
            "username": username,
            "engines_run": engines_run,
            "total_platforms_evaluated": len(platforms),
            "total_platforms_found": len(confirmed_platforms),
            "platforms": platforms,
        }

    def _overall_status(
        self,
        engine_results: list[IntegrationResult],
    ) -> InvestigationStatus:

        statuses = [r.status for r in engine_results]

        if all(s == ModuleResultStatus.FAILED for s in statuses):
            return InvestigationStatus.FAILED

        if any(s == ModuleResultStatus.FAILED for s in statuses):
            return InvestigationStatus.PARTIAL

        return InvestigationStatus.COMPLETED

    def _compute_risk_score(self, unified: dict) -> float:
        """
        More confirmed exposed profiles across more platform categories
        raises exposure/risk — this is digital-footprint exposure, not a
        judgment about the person, purely how discoverable the handle is.
        """

        found = unified["total_platforms_found"]

        if found == 0:
            return 0.0

        categories = {
            p["category"] for p in unified["platforms"] if p["confirmed"]
        }

        score = 10 * found + 5 * len(categories)

        return clamp(float(score))
