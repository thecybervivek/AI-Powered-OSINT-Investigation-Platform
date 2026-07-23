from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.email.disposable_domains import DISPOSABLE_DOMAINS
from backend.app.models.investigation import ModuleResultStatus


class DisposableEmailIntegration(AsyncBaseIntegration):
    """
    Local, network-free check of the email's domain against a curated
    list of known disposable/temporary-email providers.
    """

    source_name = "disposable_email"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        if "@" not in target:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message="Target is not a valid email address.",
            )

        domain = target.rsplit("@", 1)[-1].strip().lower()
        is_disposable = domain in DISPOSABLE_DOMAINS

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data={
                "email": target,
                "domain": domain,
                "is_disposable": is_disposable,
            },
        )
