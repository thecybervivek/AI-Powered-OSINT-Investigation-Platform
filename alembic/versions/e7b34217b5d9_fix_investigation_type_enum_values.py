"""Fix PostgreSQL investigationtype enum values.

Revision ID: e7b34217b5d9
Revises: d0e1f2a3b4c5
Create Date: 2026-07-27

Earlier migrations added some investigation type labels using lowercase
enum values, while SQLAlchemy's native Enum persists the Python enum
member names (for example FILE instead of file).

PostgreSQL enum labels are case-sensitive. This migration ensures that
all InvestigationType member names expected by the application exist in
the PostgreSQL investigationtype enum.

Existing lowercase labels are intentionally preserved.
"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e7b34217b5d9"
down_revision: Union[str, Sequence[str], None] = "d0e1f2a3b4c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# These values correspond to the Python InvestigationType enum member
# names persisted by SQLAlchemy's native PostgreSQL Enum.
_INVESTIGATION_TYPE_VALUES = (
    "USERNAME",
    "EMAIL",
    "DOMAIN",
    "IP_ADDRESS",
    "DNS",
    "URL",
    "PHONE",
    "METADATA",
    "REVERSE_IMAGE",
    "FILE",
    "SOCIAL_MEDIA",
    "BREACH",
    "THREAT_INTELLIGENCE",
    "MALWARE",
    "RISK_ASSESSMENT",
)


def upgrade() -> None:
    """Ensure every application investigation type exists in PostgreSQL."""

    bind = op.get_bind()

    if bind.dialect.name != "postgresql":
        return

    # ALTER TYPE ... ADD VALUE must be committed before the new enum
    # labels can safely be used by later transactions. Alembic's
    # autocommit block handles that requirement.
    with op.get_context().autocommit_block():
        for value in _INVESTIGATION_TYPE_VALUES:
            op.execute(
                f"ALTER TYPE investigationtype "
                f"ADD VALUE IF NOT EXISTS '{value}'"
            )


def downgrade() -> None:
    """
    PostgreSQL has no simple DROP VALUE operation for enum labels.

    Removing these labels would require recreating the enum type,
    migrating the investigations column to the replacement type and
    handling any rows already using the labels. A destructive automatic
    downgrade is therefore intentionally avoided.
    """
    pass