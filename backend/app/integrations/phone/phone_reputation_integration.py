from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.models.investigation import ModuleResultStatus


class PhoneReputationIntegration(AsyncBaseIntegration):
    """
    Phone Reputation layer (Phone Intelligence 2.0, section 5): checks
    whether a number has legitimate, publicly available security/
    reputation signals - reported spam, scam, fraud, abuse, or other
    malicious-activity flags.

    No reputation provider is wired into this deployment yet
    (PHONE_REPUTATION_API_KEY unset), so this always reports SKIPPED via
    the base class's is_configured() gate - surfaced to the analyst as
    "Not checked", never as "safe". When a real provider is added, only
    `is_configured()`/`_query()` here need to change; nothing about how
    phone_service.py consumes this source changes, since a not-configured
    SKIPPED result already contributes nothing to risk scoring.

    IMPORTANT: valid/mobile/carrier/country/existence-of-a-number facts
    from other Phone Intelligence sources are never treated as
    reputation findings - only this source's own confirmed evidence
    (once a provider exists) may report spam/scam/fraud/abuse signals.
    """

    source_name = "phone_reputation"

    def is_configured(self) -> bool:
        return bool(settings.PHONE_REPUTATION_API_KEY)

    async def _query(self, target: str) -> IntegrationResult:
        # No provider implemented yet - is_configured() always returns
        # False today, so AsyncBaseIntegration.run() never reaches this
        # method. Left in place (rather than omitted) so wiring in a
        # real reputation provider later is a self-contained change to
        # this one file.
        raise NotImplementedError(
            "PhoneReputationIntegration has no provider configured."
        )
