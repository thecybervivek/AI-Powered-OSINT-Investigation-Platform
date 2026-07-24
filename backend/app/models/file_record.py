import uuid
from datetime import datetime

from sqlalchemy import BigInteger
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import JSON
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from backend.app.models.base import BaseModel
from backend.app.models.base import TimestampMixin


class FileRecord(
    BaseModel,
    TimestampMixin,
):
    """
    One physical uploaded file, 1:1 with the Investigation that analyzed
    it. Kept separate from Investigation itself (rather than overloading
    `target`) because a file has structured, file-specific attributes -
    hashes, MIME type, size, on-disk path - that don't belong on the
    generic investigation record shared by every other module.
    """

    __tablename__ = "file_records"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    investigation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "investigations.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    original_filename: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    stored_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    storage_path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

    declared_extension: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    detected_mime_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    file_size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    md5: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    sha1: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        index=True,
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    sha512: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    extracted_metadata: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    timeline: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    investigation: Mapped["Investigation"] = relationship()  # noqa: F821

    def __repr__(self) -> str:

        return (
            f"<FileRecord("
            f"id={self.id}, "
            f"original_filename='{self.original_filename}', "
            f"sha256={self.sha256})>"
        )
