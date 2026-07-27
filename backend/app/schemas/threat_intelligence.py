import ipaddress

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator


class ThreatIntelligenceRequest(BaseModel):

    target: str = Field(
        min_length=1,
        max_length=253,
        description=(
            "An IPv4/IPv6 address, or a domain name to resolve first. "
            "Host-intelligence providers (Shodan, Censys, GreyNoise, "
            "OTX) run against the resolved IP; SecurityTrails' "
            "historical DNS runs against the domain when one is given."
        ),
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:

        value = value.strip().lower()

        try:
            ipaddress.ip_address(value)
            return value

        except ValueError:
            pass

        if not value or "/" in value or " " in value:
            raise ValueError("Target must be a valid IP address or domain name.")

        return value
