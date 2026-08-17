"""Convert investigation_results.status to a plain string column.

Revision ID: a3f5c9d2b6e4
Revises: f1a2b3c4d5e6
Create Date: 2026-08-13

WHY THIS MIGRATION EXISTS
--------------------------------------------------------------------
Same bug class as f1a2b3c4d5e6 (investigation_type), found while
extending ModuleResultStatus with FOUND/PARTIAL/UNABLE_TO_VERIFY/
NO_DATA for the Email/Phone Intelligence provider-status upgrade:
`investigation_results.status` used `SqlEnum(ModuleResultStatus)`
without `values_callable`, so SQLAlchemy has only ever sent the
Python member NAME ("SUCCESS", "NOT_FOUND", ...) to PostgreSQL, not
its lowercase `.value` - meaning the real Postgres enum type
(`moduleresultstatus`) only has uppercase labels, and every new
member added to the Python enum would need its own
`ALTER TYPE ... ADD VALUE` migration (and would silently be
uninsertable until that migration ran, exactly as documented for
investigation_type before f1a2b3c4d5e6).

Converting to a plain VARCHAR removes this class of bug the same way
f1a2b3c4d5e6 did: ModuleResultStatus becomes a code-only concern, no
Postgres-side allow-list to keep in sync, and this migration is the
last one ever required for a new provider-status value to exist.

SAFETY / COMPATIBILITY
--------------------------------------------------------------------
- `ALTER COLUMN ... TYPE VARCHAR USING status::text` is metadata-only
  for this cast direction (enum -> text) in PostgreSQL - it does not
  rewrite existing rows, and is safe with data present.
- Existing rows store the uppercase member NAME (see above). This
  migration normalizes every known uppercase name to its lowercase
  application value via an explicit CASE expression, so old and new
  rows are consistently lowercase afterward.
- The orphaned Postgres enum TYPE `moduleresultstatus` is intentionally
  NOT dropped here, matching this project's established convention
  (see f1a2b3c4d5e6) of not performing destructive/hard-to-reverse
  operations automatically.
- No-op data-shape-wise on SQLite dev databases (VARCHAR + CHECK from
  the start); the CASE-based normalization step still runs harmlessly
  there since SQLite rows are already lowercase.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a3f5c9d2b6e4"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Every ModuleResultStatus member as of this migration (name -> value).
# Kept as a static, explicit list rather than importing the live Python
# enum - pinning this migration's behavior to this point in time, same
# convention as f1a2b3c4d5e6's _NAME_TO_VALUE.
_NAME_TO_VALUE = {
    "SUCCESS": "success",
    "FOUND": "found",
    "NOT_FOUND": "not_found",
    "PARTIAL": "partial",
    "UNABLE_TO_VERIFY": "unable_to_verify",
    "NO_DATA": "no_data",
    "RATE_LIMITED": "rate_limited",
    "FAILED": "failed",
    "SKIPPED": "skipped",
}


def upgrade() -> None:

    bind = op.get_bind()

    if bind.dialect.name == "postgresql":

        op.execute(
            "ALTER TABLE investigation_results "
            "ALTER COLUMN status TYPE VARCHAR(32) "
            "USING status::text"
        )

    case_pairs = " ".join(
        f"WHEN '{name}' THEN '{value}'" for name, value in _NAME_TO_VALUE.items()
    )

    op.execute(
        f"""
        UPDATE investigation_results
        SET status = CASE status
            {case_pairs}
            ELSE status
        END
        """
    )

    if bind.dialect.name != "postgresql":

        with op.batch_alter_table("investigation_results") as batch_op:
            batch_op.alter_column(
                "status",
                type_=sa.String(length=32),
                existing_nullable=False,
            )


def downgrade() -> None:
    """
    Downgrade schema.

    Not supported - see f1a2b3c4d5e6's downgrade() for the identical
    rationale: recreating the native enum would reintroduce the exact
    name/value mismatch bug this migration removes. Restore from a
    pre-migration backup if a downgrade is truly required.
    """

    raise NotImplementedError(
        "Downgrading investigation_results.status back to a native "
        "PostgreSQL enum is not supported - it would reintroduce the "
        "enum name/value mismatch bug this migration fixes. Restore "
        "from a database backup taken before this migration if a "
        "downgrade is truly required."
    )
