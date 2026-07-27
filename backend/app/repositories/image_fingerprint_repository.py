from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.image_fingerprint import ImageFingerprint
from backend.app.repositories.base import BaseRepository


class ImageFingerprintRepository(BaseRepository[ImageFingerprint]):

    def __init__(
        self,
        db: Session,
    ) -> None:

        super().__init__(
            db,
            ImageFingerprint,
        )

    def get_by_investigation(
        self,
        investigation_id: str,
    ) -> ImageFingerprint | None:

        stmt = select(ImageFingerprint).where(
            ImageFingerprint.investigation_id == investigation_id,
        )

        return self.db.execute(stmt).scalar_one_or_none()

    def find_exact_duplicate(
        self,
        *,
        user_id: str,
        sha256: str,
        exclude_id: str | None = None,
    ) -> ImageFingerprint | None:
        """
        Byte-identical match within this user's own history - same file
        content regardless of filename.
        """

        stmt = select(ImageFingerprint).where(
            ImageFingerprint.user_id == user_id,
            ImageFingerprint.sha256 == sha256,
        )

        if exclude_id is not None:
            stmt = stmt.where(ImageFingerprint.id != exclude_id)

        return self.db.execute(stmt).scalars().first()

    def list_by_user(
        self,
        *,
        user_id: str,
        exclude_id: str | None = None,
        limit: int = 500,
    ) -> list[ImageFingerprint]:
        """
        Every prior fingerprint for this user, for perceptual (near-
        duplicate) comparison. Hamming-distance comparison can't be
        expressed as a SQL predicate on a hex string, so the caller
        scans this list in Python - `limit` bounds that scan for users
        with very large investigation histories.
        """

        stmt = (
            select(ImageFingerprint)
            .where(ImageFingerprint.user_id == user_id)
            .order_by(ImageFingerprint.created_at.desc())
            .limit(limit)
        )

        if exclude_id is not None:
            stmt = stmt.where(ImageFingerprint.id != exclude_id)

        return list(self.db.execute(stmt).scalars().all())
