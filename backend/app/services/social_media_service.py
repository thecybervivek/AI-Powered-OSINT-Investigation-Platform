import asyncio
from datetime import datetime
from datetime import timezone

from sqlalchemy.orm import Session

from backend.app.integrations.username.base_checker import PlatformCheckResult
from backend.app.integrations.username.base_checker import run_platform_checks
from backend.app.integrations.username.platforms import social_media_platforms
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.models.investigation import ModuleResultStatus
from backend.app.repositories.investigation_repository import InvestigationRepository
from backend.app.utils.risk_scoring import clamp
from backend.app.utils.risk_scoring import risk_level_from_score

# Reuses the exact same HTTP-based public existence-checking engine as
# Milestone 2 (Sherlock/Maigret/WhatsMyName), scoped to just the 8
# named platforms this milestone specifies. This is deliberately
# public-profile-existence checking only - it never authenticates,
# never scrapes private/restricted content, and never touches anything
# behind a login wall, consistent with each platform's public pages.
_PLATFORMS = social_media_platforms()


def _serialize_checks(checks: list[PlatformCheckResult]) -> list[dict]:

    return [
        {
            "platform": c.platform,
            "category": c.category,
            "exists": c.exists,
            "profile_url": c.profile_url,
            "http_status": c.http_status,
            "latency_ms": c.latency_ms,
            "error": c.error,
        }
        for c in checks
    ]


class SocialMediaIntelligenceService:
    """
    Orchestrates Milestone 9 Part 3 (Social Media Intelligence):

    - Profile Discovery / Platform Presence: checks the primary
      username's public existence across GitHub, LinkedIn, X (Twitter),
      Instagram, Facebook, Reddit, Medium, and HackerOne.
    - Username Correlation: optionally checks additional candidate
      handles (aliases) against the same platforms and reports where
      they overlap with the primary username - a starting-point signal
      for "might this be the same person", not a claim of identity.
    - Account Risk Indicators: a footprint/exposure score based on how
      discoverable the primary handle is, in the same spirit as every
      other module's risk scoring (exposure, not moral judgment).
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InvestigationRepository(db)

    async def investigate(
        self,
        *,
        user_id: str,
        username: str,
        related_usernames: list[str] | None = None,
    ) -> Investigation:

        related_usernames = related_usernames or []

        investigation = self.repository.create(
            Investigation(
                user_id=user_id,
                investigation_type=InvestigationType.SOCIAL_MEDIA,
                target=username,
                status=InvestigationStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
        )

        all_usernames = [username, *related_usernames]

        all_checks = await asyncio.gather(
            *(run_platform_checks(name, _PLATFORMS) for name in all_usernames)
        )

        primary_checks = all_checks[0]
        related_checks_by_name = dict(zip(related_usernames, all_checks[1:]))

        discovery_data = self._build_profile_discovery(username, primary_checks)

        self.repository.add_result(
            InvestigationResult(
                investigation_id=investigation.id,
                source="social_profile_discovery",
                status=(
                    ModuleResultStatus.SUCCESS
                    if any(c.exists is not None for c in primary_checks)
                    else ModuleResultStatus.FAILED
                ),
                data=discovery_data,
            )
        )

        if related_usernames:

            correlation_data = self._build_correlation(
                username,
                discovery_data["confirmed_platforms"],
                related_checks_by_name,
            )

            self.repository.add_result(
                InvestigationResult(
                    investigation_id=investigation.id,
                    source="social_username_correlation",
                    status=ModuleResultStatus.SUCCESS,
                    data=correlation_data,
                )
            )

        else:

            self.repository.add_result(
                InvestigationResult(
                    investigation_id=investigation.id,
                    source="social_username_correlation",
                    status=ModuleResultStatus.SKIPPED,
                    error_message=(
                        "No related_usernames were provided for "
                        "correlation."
                    ),
                )
            )

        risk_score, risk_notes = self._compute_risk_score(
            discovery_data,
            related_checks_by_name,
        )

        overall_status = (
            InvestigationStatus.COMPLETED
            if any(c.exists is not None for c in primary_checks)
            else InvestigationStatus.FAILED
        )

        summary = self._build_summary(username, discovery_data, risk_notes)

        return self.repository.update(
            investigation,
            status=overall_status,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            summary=summary,
            completed_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------
    # Profile Discovery / Platform Presence
    # ------------------------------------------------------

    def _build_profile_discovery(
        self,
        username: str,
        checks: list[PlatformCheckResult],
    ) -> dict:

        confirmed = [c for c in checks if c.exists is True]

        return {
            "username": username,
            "platforms_checked": len(checks),
            "confirmed_count": len(confirmed),
            "confirmed_platforms": sorted(c.platform for c in confirmed),
            "results": _serialize_checks(checks),
        }

    # ------------------------------------------------------
    # Username Correlation
    # ------------------------------------------------------

    def _build_correlation(
        self,
        primary_username: str,
        primary_confirmed_platforms: list[str],
        related_checks_by_name: dict[str, list[PlatformCheckResult]],
    ) -> dict:

        primary_confirmed_set = set(primary_confirmed_platforms)
        correlations = []

        for related_username, checks in related_checks_by_name.items():

            confirmed = sorted(
                c.platform for c in checks if c.exists is True
            )
            overlap = sorted(primary_confirmed_set & set(confirmed))

            correlations.append(
                {
                    "username": related_username,
                    "confirmed_platforms": confirmed,
                    "overlapping_platforms_with_primary": overlap,
                    "overlap_count": len(overlap),
                    "results": _serialize_checks(checks),
                }
            )

        return {
            "primary_username": primary_username,
            "related_usernames_checked": len(related_checks_by_name),
            "correlations": correlations,
        }

    # ------------------------------------------------------
    # Account Risk Indicators
    # ------------------------------------------------------

    def _compute_risk_score(
        self,
        discovery_data: dict,
        related_checks_by_name: dict[str, list[PlatformCheckResult]],
    ) -> tuple[float, list[str]]:
        """
        Scores digital-footprint EXPOSURE (how discoverable/correlatable
        the handle is across public platforms) - not a judgment of the
        person or any individual platform. Higher confirmed-platform
        counts and stronger alias overlap both raise discoverability.
        """

        score = 0.0
        notes: list[str] = []

        confirmed_count = discovery_data["confirmed_count"]

        if confirmed_count:

            # Only 8 platforms in this module's scope, so weight each
            # confirmed match more heavily than Milestone 2's broader
            # catalogue (dozens of platforms) does.
            score += clamp(confirmed_count * 12, high=70)
            notes.append(
                f"Confirmed public profile on {confirmed_count} of "
                f"{discovery_data['platforms_checked']} tracked platforms"
            )

        max_overlap = 0

        for related_username, checks in related_checks_by_name.items():

            confirmed = {c.platform for c in checks if c.exists is True}
            overlap = confirmed & set(discovery_data["confirmed_platforms"])

            if overlap:
                max_overlap = max(max_overlap, len(overlap))
                notes.append(
                    f"'{related_username}' shares {len(overlap)} "
                    f"platform(s) with the primary username - possible "
                    "alias correlation"
                )

        if max_overlap:
            score += clamp(max_overlap * 10, high=30)

        return clamp(score), notes

    def _build_summary(
        self,
        username: str,
        discovery_data: dict,
        risk_notes: list[str],
    ) -> str:

        if not risk_notes:
            return (
                f"No public profiles found for '{username}' across the "
                "tracked platforms."
            )

        return f"Social media findings for '{username}': " + "; ".join(risk_notes) + "."
