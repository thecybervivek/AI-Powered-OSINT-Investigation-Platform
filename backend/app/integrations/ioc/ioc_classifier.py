import ipaddress
import re
from enum import Enum
from urllib.parse import urlparse

from backend.app.integrations.username.base_checker import is_valid_username

_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_PATTERN = re.compile(rf"^({_DOMAIN_LABEL}\.)+{_DOMAIN_LABEL}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class IOCType(str, Enum):

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    USERNAME = "username"


def classify_ioc(raw_value: str) -> IOCType:
    """
    Classifies a raw indicator string so the IOC service can route it to
    the right existing investigation service (IP/domain/URL/email/
    username). Order matters - checks run from most to least specific
    to avoid misclassifying e.g. an IP as a "domain".
    """

    value = raw_value.strip()

    if not value:
        raise ValueError("Indicator value cannot be empty.")

    # 1. IP address - most specific, no ambiguity possible.
    try:
        ipaddress.ip_address(value)
        return IOCType.IP_ADDRESS

    except ValueError:
        pass

    # 2. URL - has a scheme, or (no scheme but) contains a path/query
    #    segment after a domain-like host, which a bare domain never has.
    candidate = value if "://" in value else f"http://{value}"
    parsed = urlparse(candidate)

    has_path_or_query = bool(parsed.path.strip("/")) or bool(parsed.query)
    has_explicit_scheme = "://" in value

    if (has_explicit_scheme or has_path_or_query) and parsed.netloc:
        return IOCType.URL

    # 3. Email - contains "@" and matches a basic address shape.
    if "@" in value and _EMAIL_PATTERN.match(value):
        return IOCType.EMAIL

    # 4. Domain - dotted label sequence with a valid-looking TLD.
    if _DOMAIN_PATTERN.match(value.lower()):
        return IOCType.DOMAIN

    # 5. Username - last resort: plausible handle characters only.
    if is_valid_username(value):
        return IOCType.USERNAME

    raise ValueError(
        f"Could not classify '{raw_value}' as an IP, domain, URL, email, "
        "or username."
    )
