from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

from backend.app.integrations.username.base_checker import is_valid_username


class SocialMediaInvestigationRequest(BaseModel):

    username: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Primary handle to check across GitHub, LinkedIn, X "
            "(Twitter), Instagram, Facebook, Reddit, Medium, and "
            "HackerOne."
        ),
    )

    related_usernames: list[str] = Field(
        default_factory=list,
        max_length=10,
        description=(
            "Optional additional handles/aliases to correlate against "
            "the same 8 platforms - e.g. variants the analyst suspects "
            "belong to the same person. Each is checked independently; "
            "the response reports which platforms each one resolved on."
        ),
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:

        value = value.strip()

        if not is_valid_username(value):
            raise ValueError(
                "Username may only contain letters, numbers, dots, "
                "underscores, and hyphens."
            )

        return value

    @field_validator("related_usernames")
    @classmethod
    def validate_related_usernames(cls, values: list[str]) -> list[str]:

        cleaned = []

        for value in values:

            value = value.strip()

            if not is_valid_username(value):
                raise ValueError(
                    f"'{value}' is not a valid username: only letters, "
                    "numbers, dots, underscores, and hyphens are allowed."
                )

            cleaned.append(value)

        return cleaned
