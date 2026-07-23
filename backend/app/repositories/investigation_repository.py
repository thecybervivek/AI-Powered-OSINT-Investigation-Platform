from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationResult
from backend.app.models.investigation import InvestigationStatus
from backend.app.models.investigation import InvestigationType
from backend.app.repositories.base import BaseRepository


class InvestigationRepository(BaseRepository[Investigation]):

    def __init__(
        self,
        db: Session,
    ) -> None:

        super().__init__(
            db,
            Investigation,
        )

    def search(
        self,
        *,
        user_id: str,
        investigation_type: InvestigationType | None = None,
        status: InvestigationStatus | None = None,
        query: str | None = None,
        offset: int = 0,
        limit: int = 20,
    ) -> tuple[list[Investigation], int]:
        """
        Filter + paginate a user's investigation history (Module 12).
        Returns (results, total_count).
        """

        stmt = select(Investigation).where(
            Investigation.user_id == user_id,
        )

        count_stmt = select(func.count()).select_from(Investigation).where(
            Investigation.user_id == user_id,
        )

        if investigation_type is not None:
            stmt = stmt.where(
                Investigation.investigation_type == investigation_type,
            )
            count_stmt = count_stmt.where(
                Investigation.investigation_type == investigation_type,
            )

        if status is not None:
            stmt = stmt.where(
                Investigation.status == status,
            )
            count_stmt = count_stmt.where(
                Investigation.status == status,
            )

        if query:
            like_pattern = f"%{query}%"

            stmt = stmt.where(
                or_(
                    Investigation.target.ilike(like_pattern),
                    Investigation.summary.ilike(like_pattern),
                )
            )
            count_stmt = count_stmt.where(
                or_(
                    Investigation.target.ilike(like_pattern),
                    Investigation.summary.ilike(like_pattern),
                )
            )

        stmt = (
            stmt.order_by(Investigation.created_at.desc())
            .offset(offset)
            .limit(limit)
        )

        results = list(self.db.execute(stmt).scalars().unique().all())
        total = self.db.execute(count_stmt).scalar_one()

        return results, total

    def get_owned(
        self,
        investigation_id: str,
        user_id: str,
    ) -> Investigation | None:
        """
        Fetch an investigation only if it belongs to the requesting user.
        Prevents IDOR across investigation records.
        """

        stmt = select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.user_id == user_id,
        )

        return self.db.execute(stmt).scalar_one_or_none()

    def add_result(
        self,
        result: InvestigationResult,
    ) -> InvestigationResult:

        self.db.add(result)
        self.db.commit()
        self.db.refresh(result)

        return result
