from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.file_record import FileRecord
from backend.app.repositories.base import BaseRepository


class FileRecordRepository(BaseRepository[FileRecord]):

    def __init__(
        self,
        db: Session,
    ) -> None:

        super().__init__(
            db,
            FileRecord,
        )

    def get_by_investigation(
        self,
        investigation_id: str,
    ) -> FileRecord | None:

        stmt = select(FileRecord).where(
            FileRecord.investigation_id == investigation_id,
        )

        return self.db.execute(stmt).scalar_one_or_none()
