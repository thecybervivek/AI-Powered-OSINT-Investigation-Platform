import httpx

import dns.asyncresolver
import dns.exception
import dns.resolver

from backend.app.core.config import settings
from backend.app.integrations.base import AsyncBaseIntegration
from backend.app.integrations.base import IntegrationResult
from backend.app.integrations.domain._resolve import resolve_to_ip
from backend.app.models.investigation import ModuleResultStatus
from backend.app.utils.http_client import request_with_retry


def _reversed_octets(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


class ASNLookupIntegration(AsyncBaseIntegration):
    """
    Looks up the origin ASN for a target IP.

    Primary source: Team Cymru's public DNS-based IP-to-ASN service
    (origin.asn.cymru.com) for IPv4 - the same well-established
    technique used by `whois -h whois.cymru.com` and countless
    network-ops tools, just over DNS instead of WHOIS.

    Team Cymru's DNS infrastructure occasionally returns SERVFAIL under
    load (dnspython raises NoNameservers for this) - production polish
    pass: rather than letting that surface as a raw, unhelpful
    exception, this now falls back to BGPView's free public REST API
    (no key required, supports both IPv4 and IPv6), and only reports
    "temporarily unavailable" if that also fails - never failing the
    whole investigation over one ASN provider being down.

    IPv6 targets skip Team Cymru entirely (its DNS scheme technically
    supports IPv6 via a different, more complex reversed-nibble format
    this integration does not implement) and go straight to BGPView,
    which handles both address families through the same simple REST
    call.
    """

    source_name = "asn_lookup"

    def is_configured(self) -> bool:
        return True

    async def _query(self, target: str) -> IntegrationResult:

        ip = await resolve_to_ip(target)

        if ip is None:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                error_message=f"Could not resolve '{target}' to an IP address.",
                data={"summary": "ASN lookup temporarily unavailable."},
            )

        if ":" in ip:
            # IPv6 - Team Cymru's DNS scheme isn't implemented for v6
            # here; BGPView handles both families through one code path.
            return await self._query_bgpview(target, ip)

        try:
            return await self._query_cymru(target, ip)

        except _ASNLookupUnavailable:
            return await self._query_bgpview(target, ip)

    async def _query_cymru(self, target: str, ip: str) -> IntegrationResult:

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
                data={
                    "resolved_target": target,
                    "ip_address": ip,
                    "summary": "No ASN record found for this address.",
                },
            )

        except dns.resolver.NoNameservers as error:
            # SERVFAIL/REFUSED from every queried nameserver - Team
            # Cymru's DNS service itself is unavailable right now, as
            # opposed to a normal "no record" answer. Fall back rather
            # than surfacing this raw exception.
            raise _ASNLookupUnavailable(str(error)) from error

        except dns.exception.Timeout as error:
            raise _ASNLookupUnavailable(str(error)) from error

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

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
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
            "asn_source": "team_cymru",
            "summary": _format_asn_summary(asn_name, asn, country),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )

    async def _query_bgpview(self, target: str, ip: str) -> IntegrationResult:
        """
        Free, no-API-key fallback covering both the "Team Cymru is
        SERVFAILing" case and native IPv6 support (which Team Cymru's
        DNS scheme, as implemented above, does not cover).
        """

        url = f"https://api.bgpview.io/ip/{ip}"

        try:

            async with httpx.AsyncClient(timeout=settings.OSINT_REQUEST_TIMEOUT_SECONDS) as client:
                response = await request_with_retry(client, "GET", url, max_retries=1)

        except Exception:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                data={"summary": "ASN lookup temporarily unavailable."},
                error_message="Both Team Cymru and the BGPView fallback were unreachable.",
            )

        if response.status_code == 429:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.RATE_LIMITED,
                data={"summary": "ASN lookup temporarily unavailable."},
                error_message="BGPView rate limit exceeded.",
            )

        if response.status_code != 200:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.FAILED,
                data={"summary": "ASN lookup temporarily unavailable."},
                error_message=f"BGPView returned HTTP {response.status_code}.",
            )

        payload = response.json().get("data", {})
        prefixes = payload.get("prefixes", []) or []
        asn = None
        asn_name = None
        country = None

        if prefixes:

            asn_info = prefixes[0].get("asn", {}) or {}
            asn = asn_info.get("asn")
            asn_name = asn_info.get("name") or asn_info.get("description")
            country = prefixes[0].get("country_code")

        if asn is None:

            return IntegrationResult(
                source=self.source_name,
                status=ModuleResultStatus.NOT_FOUND,
                data={
                    "resolved_target": target,
                    "ip_address": ip,
                    "asn_source": "bgpview",
                    "summary": "No ASN record found for this address.",
                },
            )

        data = {
            "resolved_target": target,
            "ip_address": ip,
            "asn": str(asn),
            "asn_name": asn_name,
            "bgp_prefix": prefixes[0].get("prefix") if prefixes else None,
            "country": country,
            "registry": None,
            "allocated_date": None,
            "asn_source": "bgpview",
            "summary": _format_asn_summary(asn_name, str(asn), country),
        }

        return IntegrationResult(
            source=self.source_name,
            status=ModuleResultStatus.SUCCESS,
            data=data,
        )


class _ASNLookupUnavailable(Exception):
    """Internal signal that Team Cymru's DNS service itself is down (SERVFAIL/timeout) - triggers the BGPView fallback."""


def _format_asn_summary(asn_name: str | None, asn: str | None, country: str | None) -> str:

    parts = [p for p in (asn_name, f"AS{asn}" if asn else None, country) if p]

    return " \u00b7 ".join(parts) if parts else "ASN information unavailable."


def _txt_to_string(record) -> str:
    return b"".join(record.strings).decode("utf-8", errors="replace")
