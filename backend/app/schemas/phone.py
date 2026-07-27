import re

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

# Deliberately permissive: accepts +, digits, spaces, dashes, dots, and
# parentheses (however the analyst pasted the number in) - actual
# structural validation happens in phonenumbers, not here. This regex
# only rejects obviously-not-a-phone-number input before it reaches the
# integration layer.
_PHONE_INPUT_PATTERN = re.compile(r"^[\d+\-.\s()]{3,20}$")


class PhoneInvestigationRequest(BaseModel):

    phone_number: str = Field(
        min_length=1,
        max_length=32,
        description=(
            "A phone number, ideally in international format "
            "(e.g. +14155552671). Numbers without a leading '+' must "
            "already be in a recognizable international form."
        ),
    )

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, value: str) -> str:

        value = value.strip()

        if not _PHONE_INPUT_PATTERN.match(value):
            raise ValueError(
                "Phone number may only contain digits, spaces, '+', "
                "'-', '.', and parentheses."
            )

        return value
