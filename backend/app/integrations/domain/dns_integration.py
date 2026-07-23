import dns.asyncresolver
import dns.exception
import dns.resolver

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus

_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS")


class DNSLookupIntegration(AsyncBaseIntegration):
    """
    Resolves A, AAAA, MX, TXT, and NS records for a domain. Each record
    type is queried independently so a missing record type (e.g. no
    AAAA) doesn't fail the whole lookup — it's simply reported empty.
    """

    source_name = "dns_lookup"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        domain = target.strip().lower().rstrip(".")

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.DNS_RESOLVER_TIMEOUT_SECONDS
        resolver.lifetime = settings.DNS_RESOLVER_TIMEOUT_SECONDS

        records: dict[str, list[str]] = {}
        domain_exists = False

        for record_type in _RECORD_TYPES:

            try:
                answer = await resolver.resolve(domain, record_type)
                domain_exists = True
                records[record_type] = [
                    self._format_record(record_type, record) for record in answer
                ]

            except dns.resolver.NXDOMAIN:
                # Domain itself doesn't exist — no point checking other types.
                return IntegrationResult(
                    source=self.source_name,
                    status=ModuleResultStatus.NOT_FOUND,
                    data={
                        "domain": domain,
                        "domain_exists": False,
                        "records": {},
                    },
                )

            except dns.resolver.NoAnswer:
                records[record_type] = []

            except dns.exception.Timeout as error:
                raise IntegrationTimeoutError(str(error)) from error

        return IntegrationResult(
            source=self.source_name,
            status=(
                ModuleResultStatus.SUCCESS
                if domain_exists
                else ModuleResultStatus.NOT_FOUND
            ),
            data={
                "domain": domain,
                "domain_exists": domain_exists,
                "records": records,
            },
        )

    @staticmethod
    def _format_record(record_type: str, record) -> str:

        if record_type == "MX":
            return f"{record.preference} {str(record.exchange).rstrip('.')}"

        if record_type == "TXT":
            return b"".join(record.strings).decode("utf-8", errors="replace")

        return str(record).rstrip(".")
