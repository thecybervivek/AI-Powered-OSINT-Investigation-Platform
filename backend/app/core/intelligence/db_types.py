"""
StringBackedEnum - the actual fix behind the Investigation Type
Registry: a column type that behaves exactly like SQLAlchemy's native
`Enum()` from every calling service's point of view (assign an enum
member, read back an enum member, `.value` works) but persists as a
plain VARCHAR with no PostgreSQL-side allow-list to keep in sync.

This is what makes "add a new investigation type = one line in
investigation_registry.py, zero database migrations" actually true -
without it, switching the column to a plain String() would still work
for WRITES (a (str, Enum) member's bind value already renders as its
.value on a plain String column) but reads would return a bare Python
str instead of an InvestigationType instance, breaking every existing
`some_investigation.investigation_type.value` call site across the
~15 services already built. Using this decorator keeps that entire
surface working unchanged.
"""

from enum import Enum
from typing import Any

from sqlalchemy import String
from sqlalchemy.types import TypeDecorator


class StringBackedEnum(TypeDecorator):
    """
    Usage: `mapped_column(StringBackedEnum(InvestigationType, length=64))`
    in place of `mapped_column(SqlEnum(InvestigationType))`.

    Unknown/legacy values already present in the column (e.g. from
    before a new member was registered) are returned as the plain
    string rather than raising, so a value the current enum doesn't
    (yet) recognize never crashes a read - callers that need strict
    validation should check
    backend.app.core.intelligence.investigation_registry.is_registered()
    explicitly rather than relying on this type to enforce it.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_class: type[Enum], length: int = 64, **kwargs: Any) -> None:

        super().__init__(length=length, **kwargs)
        self._enum_class = enum_class

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:

        if value is None:
            return None

        if isinstance(value, self._enum_class):
            return value.value

        # Allow passing a plain string too (e.g. "file"), matching how
        # SQLAlchemy's native Enum also accepts either form.
        return str(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:

        if value is None:
            return None

        try:
            return self._enum_class(value)

        except ValueError:
            # Unrecognized value already stored in the DB (e.g. a type
            # that existed before a code rollback, or one not yet added
            # to the Python enum) - return it as-is rather than raising,
            # so a single unexpected row can't take down every read of
            # the table it's in.
            return value
