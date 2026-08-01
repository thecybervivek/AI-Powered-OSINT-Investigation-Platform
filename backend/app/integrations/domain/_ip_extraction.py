import ipaddress


def is_public_ip(value: str) -> bool:
    """
    True if `value` is a valid IP literal that is genuinely public
    (not private/loopback/link-local/multicast/reserved/unspecified).
    False for anything unparseable or non-public. Shared by
    extract_public_ips below and by DomainIntelligenceService's
    handling of a bare-IP target submitted directly to the domain
    endpoint.
    """

    try:
        addr = ipaddress.ip_address(value.strip())

    except ValueError:
        return False

    return (
        addr.is_global
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
    )


def extract_public_ips(
    records: dict[str, list[str]],
) -> tuple[list[str], list[str]]:
    """
    Given DNS records as returned by DNSLookupIntegration (a dict of
    record type -> list of formatted string values), extracts and
    deduplicates every IP address from the A and AAAA answers, then
    splits them into (public_ips, non_public_ips).

    This is the fix for the core Domain Investigation routing bug:
    IP-dependent capabilities (ASN lookup, IP geolocation, reverse DNS)
    must run against these resolved addresses, never against the
    original domain string.

    Non-public addresses (private/loopback/link-local/multicast/
    reserved/unspecified) are returned separately rather than silently
    dropped, so the caller can report exactly which resolved addresses
    were excluded from IP-dependent intelligence and why - a domain
    resolving to a private address is itself a meaningful finding
    (e.g. split-horizon DNS, misconfiguration), not something to hide.

    Order is preserved (first-seen) within each bucket; the DNS
    resolver's own answer order already reflects any authoritative
    priority, so no further sorting is imposed here.
    """

    public: list[str] = []
    non_public: list[str] = []
    seen: set[str] = set()

    for record_type in ("A", "AAAA"):

        for raw in records.get(record_type, []) or []:

            value = raw.strip()

            if not value or value in seen:
                continue

            seen.add(value)

            try:
                ipaddress.ip_address(value)

            except ValueError:
                # Not a parseable address (shouldn't happen for A/AAAA
                # answers, but never let a malformed value crash the
                # pipeline) - excluded from both buckets.
                continue

            if is_public_ip(value):
                public.append(value)
            else:
                non_public.append(value)

    return public, non_public

