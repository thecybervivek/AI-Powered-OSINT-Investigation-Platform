from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus


class GHuntIntegration(AsyncBaseIntegration):
    """
    Optional Google-account intelligence provider, in the spirit of
    the GHunt project. Deliberately NOT a live implementation:

    - GHunt works by replaying an operator's own authenticated Google
      session cookies against internal Google APIs. Storing/using a
      personal Google session as a service credential is a materially
      different (and riskier) trust model than every other integration
      in this module, which use scoped, revocable API keys.
    - GHunt is distributed under AGPLv3, a strong-copyleft license;
      vendoring its code would obligate this project's source to be
      made available under compatible terms.
    - Google's own terms of service restrict automated/unofficial
      access to account data through this kind of session replay.

    Given those three factors together, this provider intentionally
    stays a clean SKIPPED/UNAVAILABLE placeholder rather than a working
    integration. It exists so the Email module has a stable slot for
    Google-account intelligence — and so the rest of the investigation
    demonstrably keeps working with it absent — without the platform
    actually performing session-replay against Google. Flip
    GHUNT_SESSION_CONFIGURED only after a deliberate, reviewed decision
    to accept the above trade-offs.
    """

    source_name = "ghunt"

    def is_configured(self) -> bool:
        return bool(settings.GHUNT_SESSION_CONFIGURED)

    async def _query(self, target: str) -> IntegrationResult:  # pragma: no cover
        # Not reachable while GHUNT_SESSION_CONFIGURED defaults to
        # False — is_configured() short-circuits to SKIPPED first.
        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SKIPPED,
            error_message=(
                "Google account intelligence is not implemented in "
                "this build."
            ),
        )
