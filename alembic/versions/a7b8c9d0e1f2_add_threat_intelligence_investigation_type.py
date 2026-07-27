"""Add threat_intelligence investigation type

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-07-26 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema.

    Milestone 9 Part 5 adds InvestigationType.THREAT_INTELLIGENCE =
    "threat_intelligence" to the Python enum in
    backend/app/models/investigation.py. Same pattern as the three
    prior enum-value migrations (b2c3d4e5f6a7 'file', d4e5f6a7b8c9
    'social_media', e5f6a7b8c9d0 'breach'): PostgreSQL materializes
    SQLAlchemy's Enum as a native TYPE, so new members need an explicit
    ALTER TYPE ... ADD VALUE, run outside a transaction via
    autocommit_block(). No-op on SQLite dev databases for the same
    reasons given in those migrations.
    """

    bind = op.get_bind()

    if bind.dialect.name == "postgresql":

        with op.get_context().autocommit_block():
            op.execute(
                "ALTER TYPE investigationtype ADD VALUE IF NOT EXISTS 'threat_intelligence'"
            )


def downgrade() -> None:
    """
    Downgrade schema.

    Not supported, for the same reason as the three prior enum-value
    migrations: PostgreSQL cannot remove a single value from an
    existing native enum type without recreating the type and every
    dependent column.
    """

    raise NotImplementedError(
        "Removing the 'threat_intelligence' InvestigationType enum "
        "value is not supported; PostgreSQL requires recreating the "
        "enum type and every dependent column to remove a single value."
    )
