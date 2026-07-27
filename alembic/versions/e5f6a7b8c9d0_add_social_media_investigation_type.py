"""Add social_media investigation type

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema.

    Milestone 9 Part 3 adds InvestigationType.SOCIAL_MEDIA =
    "social_media" to the Python enum in
    backend/app/models/investigation.py. Same rationale and pattern as
    b2c3d4e5f6a7's inline ALTER TYPE for 'file': PostgreSQL materializes
    SQLAlchemy's Enum as a native TYPE, so new members need an explicit
    ALTER TYPE ... ADD VALUE, run outside a transaction via
    autocommit_block(). SQLite dev databases store the same column as a
    VARCHAR + CHECK constraint and have no ALTER TYPE equivalent; since
    those are disposable, throwaway databases in this project, this
    migration intentionally no-ops there rather than doing a disruptive
    batch table-rebuild for one new allowed value.
    """

    bind = op.get_bind()

    if bind.dialect.name == "postgresql":

        with op.get_context().autocommit_block():
            op.execute(
                "ALTER TYPE investigationtype ADD VALUE IF NOT EXISTS 'social_media'"
            )


def downgrade() -> None:
    """
    Downgrade schema.

    Not supported for the same reason b2c3d4e5f6a7's inline enum change
    isn't reversible either: PostgreSQL cannot remove a single value
    from an existing native enum type without recreating the type and
    every dependent column.
    """

    raise NotImplementedError(
        "Removing the 'social_media' InvestigationType enum value is "
        "not supported; PostgreSQL requires recreating the enum type "
        "and every dependent column to remove a single value."
    )
