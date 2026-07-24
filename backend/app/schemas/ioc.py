from pydantic import BaseModel
from pydantic import Field

from backend.app.models.investigation import InvestigationType
from backend.app.schemas.investigation import InvestigationResponse


class IOCAnalysisRequest(BaseModel):

    indicator: str = Field(
        min_length=1,
        max_length=2048,
        description=(
            "Any indicator of compromise: an IP address, domain, URL, "
            "email address, or username. The type is auto-detected."
        ),
    )


class IOCAnalysisResponse(BaseModel):

    detected_type: InvestigationType = Field(
        description="The indicator type auto-detected by the IOC classifier.",
    )

    investigation: InvestigationResponse
