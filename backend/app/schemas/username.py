from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

from backend.app.integrations.username.base_checker import is_valid_username


class UsernameInvestigationRequest(BaseModel):

    username: str = Field(
        min_length=1,
        max_length=64,
        description="Handle to search for across supported platforms.",
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
