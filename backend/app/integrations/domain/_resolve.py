import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver

from backend.app.core.config import settings


async def resolve_to_ip(target: str) -> str | None:
    """
    Returns target unchanged if it's already an IP literal; otherwise
    resolves the domain's A record and returns the first address.
    Returns None if the target cannot be resolved.
    """

    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return target

    except ValueError:
        pass

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = settings.DNS_RESOLVER_TIMEOUT_SECONDS
    resolver.lifetime = settings.DNS_RESOLVER_TIMEOUT_SECONDS

    try:
        answer = await resolver.resolve(target, "A")
        return str(answer[0])

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
