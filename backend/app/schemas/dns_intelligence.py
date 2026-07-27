import re

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_PATTERN = re.compile(rf"^({_DOMAIN_LABEL}\.)+{_DOMAIN_LABEL}$")


class DNSIntelligenceRequest(BaseModel):

    domain: str = Field(
        min_length=1,
        max_length=253,
        description="A bare domain name, e.g. example.com",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:

        value = value.strip().lower()

        if not _DOMAIN_PATTERN.match(value):
            raise ValueError("Target must be a valid domain name.")

        return value
