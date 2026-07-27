import uuid
from datetime import datetime

from sqlalchemy import BigInteger
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from backend.app.models.base import BaseModel
from backend.app.models.base import TimestampMixin


class ImageFingerprint(
    BaseModel,
    TimestampMixin,
):
    """
    One analyzed image, 1:1 with the REVERSE_IMAGE Investigation that
    produced it. Kept separate from Investigation (same rationale as
    FileRecord in Milestone 6) because an image carries structured,
    image-specific attributes - cryptographic + perceptual hashes,
    dimensions, EXIF/GPS - that don't belong on the generic investigation
    record shared by every other module.

    `user_id` is denormalized from Investigation.user_id (rather than
    requiring a join every time) because duplicate/near-duplicate
    detection scans every one of a user's prior fingerprints on every
    new upload - see ImageFingerprintRepository.list_by_user().
    """

    __tablename__ = "image_fingerprints"

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

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
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

    detected_mime_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    file_size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    width: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    height: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # Cryptographic hashes - exact-duplicate detection (byte-identical file).
    md5: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)

    # Perceptual hashes (hex strings) - near-duplicate / visual-similarity
    # detection, robust to recompression, resizing, and minor edits.
    phash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    ahash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dhash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    extracted_metadata: Mapped[dict | None] = mapped_column(
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
            f"<ImageFingerprint("
            f"id={self.id}, "
            f"original_filename='{self.original_filename}', "
            f"sha256={self.sha256})>"
        )
