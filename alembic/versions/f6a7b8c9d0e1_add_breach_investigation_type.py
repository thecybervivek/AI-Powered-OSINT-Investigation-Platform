"""Add breach investigation type

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-26 00:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema.

    Milestone 9 Part 4 adds InvestigationType.BREACH = "breach" to the
    Python enum in backend/app/models/investigation.py. Same pattern as
    b2c3d4e5f6a7's inline ALTER TYPE for 'file' and d4e5f6a7b8c9's for
    'social_media': PostgreSQL materializes SQLAlchemy's Enum as a
    native TYPE, so new members need an explicit ALTER TYPE ... ADD
    VALUE, run outside a transaction via autocommit_block(). No-op on
    SQLite dev databases (VARCHAR + CHECK constraint, disposable in
    this project) for the same reasons given in those two migrations.
    """

    bind = op.get_bind()

    if bind.dialect.name == "postgresql":

        with op.get_context().autocommit_block():
            op.execute(
                "ALTER TYPE investigationtype ADD VALUE IF NOT EXISTS 'breach'"
            )


def downgrade() -> None:
    """
    Downgrade schema.

    Not supported, for the same reason as the two prior enum-value
    migrations: PostgreSQL cannot remove a single value from an
    existing native enum type without recreating the type and every
    dependent column.
    """

    raise NotImplementedError(
        "Removing the 'breach' InvestigationType enum value is not "
        "supported; PostgreSQL requires recreating the enum type and "
        "every dependent column to remove a single value."
    )
