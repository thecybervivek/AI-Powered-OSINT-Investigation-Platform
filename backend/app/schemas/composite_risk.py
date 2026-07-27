from pydantic import BaseModel
from pydantic import Field


class CompositeRiskRequest(BaseModel):

    investigation_ids: list[str] = Field(
        min_length=2,
        max_length=20,
        description=(
            "IDs of 2-20 of your own past investigations (any type) to "
            "combine into one composite risk assessment."
        ),
    )

    label: str = Field(
        default="Composite Risk Assessment",
        min_length=1,
        max_length=200,
        description="A short case/subject label for this assessment.",
    )
