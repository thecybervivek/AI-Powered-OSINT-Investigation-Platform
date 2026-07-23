import dns.asyncresolver
import dns.exception

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus

# Providers commonly used by legitimate, well-established mail systems.
# Presence of MX records pointing here nudges the domain-reputation
# heuristic upward; absence doesn't penalize (many valid domains
# self-host mail).
_MAJOR_MAIL_PROVIDERS = (
    "google.com",
    "googlemail.com",
    "outlook.com",
    "protection.outlook.com",
    "pphosted.com",
    "mimecast.com",
    "zoho.com",
    "yahoodns.net",
)


class MXLookupIntegration(AsyncBaseIntegration):
    """
    Extracts the domain from the target email and resolves its MX
    records, reporting whether the domain accepts mail at all and
    whether it's routed through a recognized major mail provider.
    """

    source_name = "mx_lookup"

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

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.DNS_RESOLVER_TIMEOUT_SECONDS
        resolver.lifetime = settings.DNS_RESOLVER_TIMEOUT_SECONDS

        try:
            answer = await resolver.resolve(domain, "MX")

        except dns.resolver.NXDOMAIN:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "email": target,
                    "domain": domain,
                    "has_mx_records": False,
                    "mx_records": [],
                    "domain_exists": False,
                },
            )

        except dns.resolver.NoAnswer:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "email": target,
                    "domain": domain,
                    "has_mx_records": False,
                    "mx_records": [],
                    "domain_exists": True,
                },
            )

        except dns.exception.Timeout as error:
            raise IntegrationTimeoutError(str(error)) from error

        mx_hosts = sorted(
            [
                str(record.exchange).rstrip(".").lower()
                for record in answer
            ],
            key=lambda host: host,
        )

        uses_major_provider = any(
            host.endswith(provider)
            for host in mx_hosts
            for provider in _MAJOR_MAIL_PROVIDERS
        )

        data = {
            "email": target,
            "domain": domain,
            "has_mx_records": True,
            "mx_records": mx_hosts,
            "domain_exists": True,
            "uses_major_mail_provider": uses_major_provider,
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )
