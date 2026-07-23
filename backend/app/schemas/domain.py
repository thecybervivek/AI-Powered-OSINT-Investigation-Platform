import ipaddress
import re

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"


class DomainInvestigationRequest(BaseModel):

    target: str = Field(
        min_length=1,
        max_length=253,
        description="A domain name (example.com) or an IPv4/IPv6 address.",
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

        if not re.fullmatch(rf"({_DOMAIN_LABEL}\.)+{_DOMAIN_LABEL}", value):
            raise ValueError(
                "Target must be a valid domain name or IP address."
            )

        return value
