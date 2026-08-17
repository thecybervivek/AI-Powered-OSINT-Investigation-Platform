import dns.asyncresolver
import dns.exception
import dns.resolver

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus

_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV")

# Queried separately from _RECORD_TYPES: presence-only DNSSEC check.
# This is NOT full DNSSEC chain-of-trust validation (that requires
# validating signatures up to a trust anchor, a materially bigger
# undertaking) - it only reports whether DS records exist at the
# parent zone and DNSKEY records exist at the domain's own
# authoritative servers, which is what spec section 5 asks for
# ("DS/DNSKEY presence where appropriate").
_DNSSEC_RECORD_TYPES = ("DS", "DNSKEY")


class DNSLookupIntegration(AsyncBaseIntegration):
    """
    Resolves A, AAAA, MX, TXT, NS, CNAME, SOA, and CAA records for a
    domain. Each record type is queried independently so a missing
    record type (e.g. no AAAA, no CAA) doesn't fail the whole lookup —
    it's simply reported empty.
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
                "dnssec": await self._check_dnssec_presence(resolver, domain),
            },
        )

    @staticmethod
    async def _check_dnssec_presence(resolver, domain: str) -> dict:
        """
        Presence-only check (see _DNSSEC_RECORD_TYPES docstring above) -
        NOT full DNSSEC validation. Each record type is queried
        independently and never raises: NXDOMAIN/NoAnswer/Timeout all
        mean "not observed", not "check failed", since most domains
        legitimately don't have DNSSEC deployed at all.
        """

        presence: dict[str, bool] = {}

        for record_type in _DNSSEC_RECORD_TYPES:

            try:
                await resolver.resolve(domain, record_type)
                presence[record_type] = True

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                presence[record_type] = False

            except (dns.exception.Timeout, dns.exception.DNSException):
                # Genuinely couldn't determine this one - distinct from
                # a confirmed absence, so it's left out of `presence`
                # entirely rather than defaulted to False.
                continue

        return {
            "ds_present": presence.get("DS"),
            "dnskey_present": presence.get("DNSKEY"),
            "signed": bool(presence.get("DS")) and bool(presence.get("DNSKEY")),
        }

    @staticmethod
    def _format_record(record_type: str, record) -> str:

        if record_type == "MX":
            return f"{record.preference} {str(record.exchange).rstrip('.')}"

        if record_type == "TXT":
            return b"".join(record.strings).decode("utf-8", errors="replace")

        return str(record).rstrip(".")
