import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus


class ReverseDNSIntegration(AsyncBaseIntegration):
    """
    Resolves the PTR record(s) for an IP address target, revealing the
    hostname(s) associated with it (hosting provider, reverse-mapped
    domain, etc). No-ops with NOT_FOUND for non-IP targets rather than
    failing, so the same module can run across mixed domain/IP batches.
    """

    source_name = "reverse_dns"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        try:
            ip = ipaddress.ip_address(target.strip())

        except ValueError:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SKIPPED,
                error_message="Target is not an IP address; skipping reverse DNS.",
            )

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.DNS_RESOLVER_TIMEOUT_SECONDS
        resolver.lifetime = settings.DNS_RESOLVER_TIMEOUT_SECONDS

        reverse_name = dns.reversename.from_address(str(ip))

        try:
            answer = await resolver.resolve(reverse_name, "PTR")

        except dns.resolver.NXDOMAIN:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"ip_address": str(ip), "hostnames": []},
            )

        except dns.resolver.NoAnswer:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"ip_address": str(ip), "hostnames": []},
            )

        except dns.exception.Timeout as error:
            raise IntegrationTimeoutError(str(error)) from error

        hostnames = [str(record).rstrip(".") for record in answer]

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data={"ip_address": str(ip), "hostnames": hostnames},
        )
