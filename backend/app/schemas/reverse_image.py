from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict

from backend.app.schemas.investigation import InvestigationResponse


class ImageFingerprintResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    original_filename: str

    detected_mime_type: str | None = None

    file_size_bytes: int

    width: int | None = None

    height: int | None = None

    md5: str

    sha1: str

    sha256: str

    sha512: str

    phash: str | None = None

    ahash: str | None = None

    dhash: str | None = None

    extracted_metadata: dict | None = None

    uploaded_at: datetime


class ReverseImageInvestigationResponse(BaseModel):
    """
    Combines the generic Investigation envelope (status, risk, per-source
    InvestigationResult rows - including duplicate_detection) with the
    image-specific fingerprint record, mirroring FileInvestigationResponse
    from Milestone 6.
    """

    investigation: InvestigationResponse

    image: ImageFingerprintResponse
