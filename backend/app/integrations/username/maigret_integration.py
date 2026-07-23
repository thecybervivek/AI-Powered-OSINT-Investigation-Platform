from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.username.base_checker import is_valid_username
from backend.app.integrations.username.base_checker import run_platform_checks
from backend.app.integrations.username.platforms import maigret_platforms
from backend.app.models.investigation import ModuleResultStatus


class MaigretIntegration(AsyncBaseIntegration):
    """
    Maigret-style engine: broader coverage of identity/forum/messaging
    platforms than Sherlock, and reports a simple per-site confidence
    score based on the detection method's reliability.
    """

    source_name = "maigret"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        if not is_valid_username(target):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message="Invalid username format.",
            )

        checks = await run_platform_checks(target, maigret_platforms())

        found = [c for c in checks if c.exists is True]
        not_found = [c for c in checks if c.exists is False]

        results = []

        for c in checks:

            # Status-code detection is more reliable than body-string
            # sniffing, which can be defeated by JS-rendered pages.
            site_confidence = 0.9 if c.http_status is not None and c.error is None else 0.4

            results.append(
                {
                    "platform": c.platform,
                    "category": c.category,
                    "exists": c.exists,
                    "profile_url": c.profile_url,
                    "http_status": c.http_status,
                    "latency_ms": c.latency_ms,
                    "site_confidence": site_confidence,
                    "error": c.error,
                }
            )

        data = {
            "username": target,
            "platforms_checked": len(checks),
            "profiles_found": len(found),
            "results": results,
        }

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
