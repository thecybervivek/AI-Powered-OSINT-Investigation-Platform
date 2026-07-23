from typing import Generic
from typing import Type
from typing import TypeVar

from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.base import BaseModel

ModelType = TypeVar("ModelType", bound=BaseModel)


class BaseRepository(Generic[ModelType]):
    """
    Generic CRUD repository. Concrete repositories (e.g. InvestigationRepository)
    subclass this and add domain-specific query methods on top.
    """

    def __init__(
        self,
        db: Session,
        model: Type[ModelType],
    ) -> None:

        self.db = db
        self.model = model

    def get(
        self,
        id_: str,
    ) -> ModelType | None:

        return self.db.get(
            self.model,
            id_,
        )

    def list(
        self,
        *,
        offset: int = 0,
        limit: int = 20,
        order_by=None,
    ) -> list[ModelType]:

        stmt = select(self.model)

        if order_by is not None:
            stmt = stmt.order_by(order_by)

        stmt = stmt.offset(offset).limit(limit)

        return list(
            self.db.execute(stmt).scalars().all()
        )

    def count(self) -> int:

        stmt = select(func.count()).select_from(self.model)

        return self.db.execute(stmt).scalar_one()

    def create(
        self,
        obj: ModelType,
    ) -> ModelType:

        self.db.add(obj)
        self.db.commit()
        self.db.refresh(obj)

        return obj

    def update(
        self,
        obj: ModelType,
        **fields,
    ) -> ModelType:

        for key, value in fields.items():
            setattr(obj, key, value)

        self.db.commit()
        self.db.refresh(obj)

        return obj

    def delete(
        self,
        obj: ModelType,
    ) -> None:

        self.db.delete(obj)
        self.db.commit()
