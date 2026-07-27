import re

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_PATTERN = re.compile(rf"^({_DOMAIN_LABEL}\.)+{_DOMAIN_LABEL}$")


class BreachInvestigationRequest(BaseModel):

    target: str = Field(
        min_length=3,
        max_length=253,
        description=(
            "An email address (checks HIBP + DeHashed + EmailRep) or a "
            "bare domain (checks DeHashed's domain-wide search only)."
        ),
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:

        value = value.strip().lower()

        if "@" in value:

            if not _EMAIL_PATTERN.match(value):
                raise ValueError("Target looks like an email but is not valid.")

            return value

        if not _DOMAIN_PATTERN.match(value):
            raise ValueError(
                "Target must be a valid email address or a bare domain name."
            )

        return value
