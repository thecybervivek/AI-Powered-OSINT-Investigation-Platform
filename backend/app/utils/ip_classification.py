"""
IP address category classification.

Python's stdlib `ipaddress` module's `is_private`/`is_reserved`/etc.
properties don't fully cover every category OSINT analysts care about
distinguishing - most notably, Carrier-Grade NAT (RFC 6598,
100.64.0.0/10) is NOT flagged by `is_private` at all (verified
directly against the stdlib - see this module's test file), and
"documentation"/"broadcast" have no dedicated property either even
though `is_private`/`is_reserved` happen to cover parts of them. This
module gives each category its own explicit, testable check so an
investigation can short-circuit external lookups (geolocation, ASN,
reputation) that make no sense for a non-routable address, and instead
show the analyst why.
"""

import ipaddress
from enum import Enum

# RFC 6598 - Shared Address Space, used by ISPs for Carrier-Grade NAT.
_CGNAT_RANGE_V4 = ipaddress.ip_network("100.64.0.0/10")

# RFC 5737 - TEST-NET-1/2/3, reserved for documentation/examples.
_DOCUMENTATION_RANGES_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

# RFC 3849 - IPv6 documentation range.
_DOCUMENTATION_RANGE_V6 = ipaddress.ip_network("2001:db8::/32")

_BROADCAST_V4 = ipaddress.ip_address("255.255.255.255")


class IPAddressCategory(str, Enum):

    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    CARRIER_GRADE_NAT = "carrier_grade_nat"
    DOCUMENTATION = "documentation"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"


_ANALYST_GUIDANCE = {
    IPAddressCategory.PUBLIC: None,  # normal case - proceed with lookups
    IPAddressCategory.PRIVATE: (
        "This is a private (RFC 1918 / RFC 4193) address, only routable "
        "within a local network. Geolocation, ASN, and reputation "
        "lookups do not apply - it cannot be attributed to any public "
        "internet-facing organization or location."
    ),
    IPAddressCategory.LOOPBACK: (
        "This is a loopback address, referring to the local host itself. "
        "It has no meaningful external attribution."
    ),
    IPAddressCategory.LINK_LOCAL: (
        "This is a link-local address, valid only on the local network "
        "segment. It cannot be attributed to any external location or "
        "organization."
    ),
    IPAddressCategory.CARRIER_GRADE_NAT: (
        "This address is in the Carrier-Grade NAT range (RFC 6598), used "
        "internally by ISPs to share public IPs across many customers. "
        "It cannot be attributed to a specific individual or "
        "organization from this address alone."
    ),
    IPAddressCategory.DOCUMENTATION: (
        "This address is reserved for documentation/examples (RFC 5737 / "
        "RFC 3849) and is never legitimately routed on the public "
        "internet. Any real traffic claiming this source is anomalous."
    ),
    IPAddressCategory.MULTICAST: (
        "This is a multicast address, used for one-to-many delivery, not "
        "a single host. Host attribution does not apply."
    ),
    IPAddressCategory.BROADCAST: (
        "This is the limited broadcast address and does not identify a "
        "single host."
    ),
    IPAddressCategory.UNSPECIFIED: (
        "This is the unspecified address (0.0.0.0 / ::), used as a "
        "placeholder meaning 'no address' - it cannot be investigated."
    ),
    IPAddressCategory.RESERVED: (
        "This address falls in an IANA-reserved range not allocated for "
        "general internet use. External lookups are unlikely to return "
        "meaningful results."
    ),
}


def classify_ip(ip_str: str) -> IPAddressCategory:
    """
    Categorizes an IP address, checking the most specific special-use
    categories before falling back to the generic PRIVATE/RESERVED/
    PUBLIC buckets - order matters (e.g. loopback is also `is_private`
    under the stdlib, so it must be checked first to get the more
    specific, useful category).
    """

    ip = ipaddress.ip_address(ip_str.strip())

    if ip.is_unspecified:
        return IPAddressCategory.UNSPECIFIED

    if ip.is_loopback:
        return IPAddressCategory.LOOPBACK

    if ip.is_link_local:
        return IPAddressCategory.LINK_LOCAL

    if ip.version == 4 and ip in _CGNAT_RANGE_V4:
        return IPAddressCategory.CARRIER_GRADE_NAT

    if ip.version == 4 and any(ip in net for net in _DOCUMENTATION_RANGES_V4):
        return IPAddressCategory.DOCUMENTATION

    if ip.version == 6 and ip in _DOCUMENTATION_RANGE_V6:
        return IPAddressCategory.DOCUMENTATION

    if ip.version == 4 and ip == _BROADCAST_V4:
        return IPAddressCategory.BROADCAST

    if ip.is_multicast:
        return IPAddressCategory.MULTICAST

    if ip.is_private:
        return IPAddressCategory.PRIVATE

    if ip.is_reserved:
        return IPAddressCategory.RESERVED

    return IPAddressCategory.PUBLIC


def analyst_guidance_for(category: IPAddressCategory) -> str | None:
    """Returns the human-readable explanation for a non-public category, or None for PUBLIC (proceed as normal)."""

    return _ANALYST_GUIDANCE[category]


def is_routable_public(ip_str: str) -> bool:
    """Convenience check: True only for PUBLIC - the one category where external lookups make sense."""

    return classify_ip(ip_str) == IPAddressCategory.PUBLIC
