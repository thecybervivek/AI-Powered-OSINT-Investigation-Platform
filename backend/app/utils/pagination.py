import math

from fastapi import Query
from pydantic import BaseModel


class PageParams(BaseModel):
    """
    Dependency-injectable pagination params.
    Usage: page_params: PageParams = Depends(PageParams)
    """

    page: int = 1
    page_size: int = 20

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size


def page_params(
    page: int = Query(
        default=1,
        ge=1,
        description="1-indexed page number.",
    ),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Items per page (max 100).",
    ),
) -> PageParams:

    return PageParams(
        page=page,
        page_size=page_size,
    )


def build_paginated_meta(
    *,
    total: int,
    page: int,
    page_size: int,
) -> dict:

    total_pages = math.ceil(total / page_size) if page_size else 0

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }
