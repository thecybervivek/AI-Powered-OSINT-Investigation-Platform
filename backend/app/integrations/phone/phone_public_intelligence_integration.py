from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus


class PhonePublicIntelligenceIntegration(AsyncBaseIntegration):
    """
    Public Intelligence layer (Phone Intelligence 2.0, section 7):
    surfaces only legitimately, publicly indexed references to the
    number - indexed pages, public business/organization listings, or
    public security/reputation reports. This is explicitly NOT a
    deanonymization tool: it must never access private accounts, bypass
    login/CAPTCHA/anti-bot protections, use stolen credentials or
    authenticated cookies, or perform brute-force/password-reset-flow
    enumeration. Any source that blocks automated access is represented
    as BLOCKED/UNKNOWN with a reason, never silently converted to
    NOT_FOUND.

    No public-search provider is wired into this deployment yet
    (PHONE_PUBLIC_INTEL_API_KEY unset), so this always reports SKIPPED
    via the base class's is_configured() gate - surfaced to the analyst
    as "Not checked", not as "nothing public exists".
    """

    source_name = "phone_public_intelligence"

    def is_configured(self) -> bool:
        return bool(settings.PHONE_PUBLIC_INTEL_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:
        # No provider implemented yet - is_configured() always returns
        # False today, so AsyncBaseIntegration.run() never reaches this
        # method.
        raise NotImplementedError(
            "PhonePublicIntelligenceIntegration has no provider configured."
        )
