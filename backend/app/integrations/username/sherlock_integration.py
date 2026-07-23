from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.username.base_checker import is_valid_username
from backend.app.integrations.username.base_checker import run_platform_checks
from backend.app.integrations.username.platforms import sherlock_platforms
from backend.app.models.investigation import ModuleResultStatus


class SherlockIntegration(AsyncBaseIntegration):
    """
    Sherlock-style engine: checks a username against social/dev/media
    platforms, relying primarily on HTTP status codes and known
    "not found" markers to determine existence.
    """

    source_name = "sherlock"

    def is_configured(self) -> bool:
        return True  # No API key required — plain HTTP probing.

    async def _query(self, target: str) -> IntegrationResult:

        if not is_valid_username(target):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message="Invalid username format.",
            )

        checks = await run_platform_checks(target, sherlock_platforms())

        found = [c for c in checks if c.exists is True]
        not_found = [c for c in checks if c.exists is False]
        inconclusive = [c for c in checks if c.exists is None]

        data = {
            "username": target,
            "platforms_checked": len(checks),
            "profiles_found": len(found),
            "results": [
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
            ],
        }

        # SUCCESS whenever we got at least one conclusive check, regardless
        # of whether a profile was actually found — "confirmed absent" is
        # still usable intelligence. FAILED only when every platform check
        # was inconclusive (network errors across the board).
        if found:
            status = ModuleResultStatus.SUCCESS
        elif not_found:
            status = ModuleResultStatus.NOT_FOUND
        else:
            status = ModuleResultStatus.FAILED

        return IntegrationResult(
            source=self.source_name,
            status=status,
            data=data,
        )
