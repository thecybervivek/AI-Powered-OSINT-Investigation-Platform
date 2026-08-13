from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.email.base_checker import AccountPresenceState
from backend.app.integrations.email.base_checker import run_presence_checks
from backend.app.integrations.email.checkers import ALL_CHECKERS
from backend.app.models.investigation import ModuleResultStatus


class AccountPresenceIntegration(AsyncBaseIntegration):
    """
    Account & Social Presence engine: checks whether an email address
    has a registered account across the platforms in checkers/,
    architecturally equivalent to the username module's engines (one
    engine, many independently-testable per-platform checks fanned out
    concurrently) rather than one large multi-purpose file.

    Internal source name stays "account_presence" - a neutral,
    provider-agnostic identifier (never shown to the user as-is; the
    frontend labels this data "Account & Social Presence").
    """

    source_name = "account_presence"

    def is_configured(self) -> bool:
        return True  # No API key required - public endpoints only.

    async def _query(self, target: str) -> IntegrationResult:

        if "@" not in target:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message="Target is not a valid email address.",
            )

        checks = await run_presence_checks(target, ALL_CHECKERS)

        confirmed = [c for c in checks if c.status == AccountPresenceState.CONFIRMED]

        data = {
            "email": target,
            "platforms_checked": len(checks),
            "accounts_confirmed": len(confirmed),
            "results": [c.to_dict() for c in checks],
        }

        # INTEGRATION EXECUTION STATUS vs. PLATFORM STATUS are
        # deliberately separate concerns. This ModuleResultStatus
        # describes whether the sweep itself executed and produced
        # structured results - NOT the aggregate verdict across 15
        # independent platforms (that granular verdict lives per-row
        # in data["results"], and is what normalization.py/the
        # frontend read).
        #
        # Every checker (see checkers/*.py) already catches its own
        # errors and returns a FAILED/UNKNOWN PlatformCheckResult
        # rather than raising, so run_presence_checks completing at
        # all means we have a full, structured, checked-every-platform
        # result - that is a successful integration run even when
        # every individual platform came back UNKNOWN/BLOCKED/
        # RATE_LIMITED (e.g. GitHub/SoundCloud returning unexpected
        # HTTP 403/401 while every other platform is a by-design
        # BLOCKED stub - a real, previously-reproduced case). Reducing
        # 15 independent platform outcomes to one pass/fail engine
        # verdict silently discarded that structured evidence
        # downstream (see normalization.py) - collapsing "nothing was
        # conclusive" into a generic FAILED is exactly the bug this
        # fixes.
        status = ModuleResultStatus.SUCCESS if checks else ModuleResultStatus.FAILED

        return IntegrationResult(
            source=self.source_name,
            status=status,
            data=data,
        )
