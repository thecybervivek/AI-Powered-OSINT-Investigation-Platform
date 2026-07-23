import dns.asyncresolver
import dns.exception
import dns.resolver

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._resolve import resolve_to_ip
from backend.app.integrations.exceptions import IntegrationTimeoutError
from backend.app.models.investigation import ModuleResultStatus


def _reversed_octets(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


class ASNLookupIntegration(AsyncBaseIntegration):
    """
    Looks up the origin ASN for an IPv4 target using Team Cymru's public
    DNS-based IP-to-ASN service (origin.asn.cymru.com), then resolves the
    AS number to a human-readable name via asn.cymru.com. This is the
    same well-established technique used by `whois -h whois.cymru.com`
    and countless network-ops tools, just over DNS instead of WHOIS.
    """

    source_name = "asn_lookup"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        ip = await resolve_to_ip(target)

        if ip is None or ":" in ip:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.SKIPPED,
                error_message="ASN lookup currently supports IPv4 targets only.",
            )

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.DNS_RESOLVER_TIMEOUT_SECONDS
        resolver.lifetime = settings.DNS_RESOLVER_TIMEOUT_SECONDS

        origin_query = f"{_reversed_octets(ip)}.origin.asn.cymru.com"

        try:
            origin_answer = await resolver.resolve(origin_query, "TXT")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={"resolved_target": target, "ip_address": ip},
            )

        except dns.exception.Timeout as error:
            raise IntegrationTimeoutError(str(error)) from error

        # Format: "ASN | BGP Prefix | Country | Registry | Allocated"
        fields = _txt_to_string(origin_answer[0]).split("|")
        fields = [f.strip() for f in fields]

        asn = fields[0] if len(fields) > 0 else None
        bgp_prefix = fields[1] if len(fields) > 1 else None
        country = fields[2] if len(fields) > 2 else None
        registry = fields[3] if len(fields) > 3 else None
        allocated = fields[4] if len(fields) > 4 else None

        asn_name = None

        if asn:

            try:
                name_answer = await resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
                # Format: "ASN | Country | Registry | Allocated | AS Name"
                name_fields = [f.strip() for f in _txt_to_string(name_answer[0]).split("|")]
                asn_name = name_fields[-1] if name_fields else None

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass

        data = {
            "resolved_target": target,
            "ip_address": ip,
            "asn": asn,
            "asn_name": asn_name,
            "bgp_prefix": bgp_prefix,
            "country": country,
            "registry": registry,
            "allocated_date": allocated,
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


def _txt_to_string(record) -> str:
    return b"".join(record.strings).decode("utf-8", errors="replace")
