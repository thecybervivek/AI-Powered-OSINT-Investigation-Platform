from urllib.parse import urlparse

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator


class URLInvestigationRequest(BaseModel):

    url: str = Field(
        min_length=1,
        max_length=2048,
        description="A full URL, e.g. https://example.com/path",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:

        value = value.strip()
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "URL must include an http:// or https:// scheme and a host."
            )

        return value
