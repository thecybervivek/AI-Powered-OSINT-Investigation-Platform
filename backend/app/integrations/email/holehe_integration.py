from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.email.account_presence import AccountPresenceState
from backend.app.integrations.email.account_presence import run_presence_checks
from backend.app.models.investigation import ModuleResultStatus


class HoleheIntegration(AsyncBaseIntegration):
    """
    Account & Social Presence engine: checks whether an email address
    has a registered account on a small set of platforms, using each
    platform's own public sign-up/availability endpoint (technique
    catalogued by the open-source `holehe` project — see
    account_presence.py's module docstring for the attribution note).
    No API key required.

    Internal source name stays "holehe" (this class/source identifier
    is never shown to the user — the frontend labels this data
    "Account & Social Presence").

    Distinct from the username module's SherlockIntegration in that a
    positive result here means "this address is registered", not "a
    public profile page exists".
    """

    source_name = "holehe"

    def is_configured(self) -> bool:
        return True  # No API key required — public endpoints only.

    async def _query(self, target: str) -> IntegrationResult:

        if "@" not in target:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message="Target is not a valid email address.",
            )

        checks = await run_presence_checks(target)

        confirmed = [c for c in checks if c.status == AccountPresenceState.CONFIRMED]
        not_found = [c for c in checks if c.status == AccountPresenceState.NOT_FOUND]
        blocked_or_limited = [
            c for c in checks
            if c.status in (AccountPresenceState.BLOCKED, AccountPresenceState.RATE_LIMITED)
        ]

        data = {
            "email": target,
            "platforms_checked": len(checks),
            "accounts_confirmed": len(confirmed),
            "results": [
                {
                    "platform": c.platform,
                    "domain": c.domain,
                    "category": c.category,
                    "status": c.status.value,
                    "confidence": c.confidence,
                    "evidence": c.evidence,
                    "http_status": c.http_status,
                    "checked_at": c.checked_at,
                    "provider_reason": c.provider_reason,
                    "profile_url": c.profile_url,
                    "latency_ms": c.latency_ms,
                }
                for c in checks
            ],
        }

        # Mirrors SherlockIntegration's precedence: any conclusive
        # CONFIRMED -> SUCCESS (even if other platforms were
        # inconclusive); no confirms but at least one conclusive
        # NOT_FOUND -> NOT_FOUND ("we checked, nothing registered
        # there"); RATE_LIMITED only if every check was blocked/
        # rate-limited (so a rate-limit/block doesn't get quietly
        # reported as a plain FAILED); otherwise FAILED (network
        # errors or unrecognized responses across the board).
        if confirmed:
            status = ModuleResultStatus.SUCCESS
        elif not_found:
            status = ModuleResultStatus.NOT_FOUND
        elif checks and len(blocked_or_limited) == len(checks):
            status = ModuleResultStatus.RATE_LIMITED
        else:
            status = ModuleResultStatus.FAILED

        return IntegrationResult(
            source=self.source_name,
            status=status,
            data=data,
        )
