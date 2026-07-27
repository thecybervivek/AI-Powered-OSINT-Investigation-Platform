"""Add risk_assessment investigation type

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-07-26 03:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c9d0e1f2a3b4'
down_revision: Union[str, Sequence[str], None] = 'b8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema.

    Milestone 9 Part 8 adds InvestigationType.RISK_ASSESSMENT =
    "risk_assessment" to the Python enum in
    backend/app/models/investigation.py - the Risk Engine Extension's
    composite, cross-investigation analysis record. Same pattern as the
    five prior enum-value migrations: PostgreSQL materializes
    SQLAlchemy's Enum as a native TYPE, so new members need an explicit
    ALTER TYPE ... ADD VALUE, run outside a transaction via
    autocommit_block(). No-op on SQLite dev databases for the same
    reasons given in those migrations.
    """

    bind = op.get_bind()

    if bind.dialect.name == "postgresql":

        with op.get_context().autocommit_block():
            op.execute(
                "ALTER TYPE investigationtype ADD VALUE IF NOT EXISTS 'risk_assessment'"
            )


def downgrade() -> None:
    """
    Downgrade schema.

    Not supported, for the same reason as the five prior enum-value
    migrations: PostgreSQL cannot remove a single value from an
    existing native enum type without recreating the type and every
    dependent column.
    """

    raise NotImplementedError(
        "Removing the 'risk_assessment' InvestigationType enum value is "
        "not supported; PostgreSQL requires recreating the enum type "
        "and every dependent column to remove a single value."
    )
