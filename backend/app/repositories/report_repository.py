from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.report import Report
from backend.app.models.report import ReportStatus
from backend.app.repositories.base import BaseRepository


class ReportRepository(BaseRepository[Report]):

    def __init__(
        self,
        db: Session,
    ) -> None:

        super().__init__(
            db,
            Report,
        )

    def get_owned(
        self,
        report_id: str,
        user_id: str,
    ) -> Report | None:
        """
        Fetch a report only if it belongs to the requesting user.
        Prevents IDOR across report records.
        """

        stmt = select(Report).where(
            Report.id == report_id,
            Report.user_id == user_id,
        )

        return self.db.execute(stmt).scalar_one_or_none()

    def search(
        self,
        *,
        user_id: str,
        status: ReportStatus | None = None,
        query: str | None = None,
        offset: int = 0,
        limit: int = 20,
    ) -> tuple[list[Report], int]:
        """
        Filter + paginate a user's reports.
        Returns (results, total_count).
        """

        stmt = select(Report).where(Report.user_id == user_id)
        count_stmt = select(func.count()).select_from(Report).where(
            Report.user_id == user_id,
        )

        if status is not None:
            stmt = stmt.where(Report.status == status)
            count_stmt = count_stmt.where(Report.status == status)

        if query:
            like_pattern = f"%{query}%"
            stmt = stmt.where(Report.title.ilike(like_pattern))
            count_stmt = count_stmt.where(Report.title.ilike(like_pattern))

        stmt = (
            stmt.order_by(Report.created_at.desc())
            .offset(offset)
            .limit(limit)
        )

        results = list(self.db.execute(stmt).scalars().all())
        total = self.db.execute(count_stmt).scalar_one()

        return results, total

    def delete_owned(
        self,
        report_id: str,
        user_id: str,
    ) -> bool:

        report = self.get_owned(report_id, user_id)

        if report is None:
            return False

        self.delete(report)

        return True
