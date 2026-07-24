from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict

from backend.app.schemas.investigation import InvestigationResponse


class FileRecordResponse(BaseModel):

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    original_filename: str

    declared_extension: str | None = None

    detected_mime_type: str | None = None

    file_size_bytes: int

    md5: str

    sha1: str

    sha256: str

    sha512: str

    extracted_metadata: dict | None = None

    timeline: dict | None = None

    uploaded_at: datetime


class FileInvestigationResponse(BaseModel):
    """
    Combines the generic Investigation envelope (status, risk, per-source
    InvestigationResult rows) with the file-specific record (hashes,
    metadata, timeline) in a single response for the upload endpoint.
    """

    investigation: InvestigationResponse

    file: FileRecordResponse
