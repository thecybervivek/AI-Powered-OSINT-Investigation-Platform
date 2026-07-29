"""Convert investigation_type to a plain string column (registry-backed).

Revision ID: f1a2b3c4d5e6
Revises: e7b34217b5d9
Create Date: 2026-07-28

WHY THIS MIGRATION EXISTS
--------------------------------------------------------------------
Auditing this baseline surfaced a real, load-bearing bug: SQLAlchemy's
native `Enum` column type persists a Python Enum member's `.name`
(e.g. "FILE") rather than its `.value` (e.g. "file") unless the column
is declared with `values_callable`. This project's `investigation_type`
column never used `values_callable`, so PostgreSQL's native enum type
has only ever actually needed the UPPERCASE member names as its valid
labels - not the lowercase `.value` strings every one of this
project's per-module migrations added
(b2c3d4e5f6a7/e5f6a7b8c9d0/f6a7b8c9d0e1/a7b8c9d0e1f2/b8c9d0e1f2a3/
c9d0e1f2a3b4, all "ADD VALUE 'lowercase_value'"). Those lowercase
labels were harmlessly unused; the missing uppercase labels for every
Milestone-9 module (FILE/SOCIAL_MEDIA/BREACH/THREAT_INTELLIGENCE/
MALWARE/RISK_ASSESSMENT) would have made inserting ANY investigation of
those types fail against real PostgreSQL until this baseline's
e7b34217b5d9 migration added the correct uppercase labels.

Converting to a plain VARCHAR removes this entire class of bug by
construction: there is no PostgreSQL-side allow-list to keep in sync
with the Python enum at all going forward. The single source of truth
for which investigation_type values are valid moves to
backend/app/core/intelligence/investigation_registry.py, enforced at
the application layer (see is_registered()) rather than the database
layer - adding a new investigation type is now a code change with NO
accompanying database migration required.

SAFETY / COMPATIBILITY
--------------------------------------------------------------------
- `ALTER COLUMN ... TYPE VARCHAR USING investigation_type::text` is a
  metadata-only change in PostgreSQL for this cast direction (enum ->
  text) - it does not rewrite the underlying data, only the column's
  reported type, and is safe to run with existing rows present.
- Existing rows currently store the uppercase enum member NAME (see
  above). This migration explicitly normalizes every known uppercase
  name to its lowercase application value with an inline CASE
  expression, so both old and new rows are consistently lowercase
  after this migration - no row is silently left inconsistent.
- The orphaned PostgreSQL enum TYPE `investigationtype` is intentionally
  NOT dropped here. It is harmless once unused (no column references
  it), and dropping database types is exactly the kind of destructive,
  hard-to-reverse operation this project's own conventions (see every
  prior downgrade() in this directory) avoid doing automatically.
  Account 1: safe to drop in a later, deliberate cleanup migration once
  confirmed nothing else references it (`DROP TYPE IF EXISTS
  investigationtype;`), not required for this fix to be correct.
- No-op on SQLite dev databases: SQLite never had a native enum for
  this column (VARCHAR + CHECK constraint from the start), so there is
  nothing to convert there; the CASE-based data normalization step
  still runs (harmlessly - SQLite rows are already lowercase, since
  SQLite's CHECK constraint has always compared against the Python
  `.value` strings, not `.name`).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "e7b34217b5d9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Every InvestigationType member as of this migration (name -> value).
# Kept as a static, explicit list rather than importing the live Python
# enum, so this migration's behavior is pinned to this point in time
# and unaffected by future enum changes (the whole point of this
# migration is that future changes never need a migration at all).
_NAME_TO_VALUE = {
    "USERNAME": "username",
    "EMAIL": "email",
    "DOMAIN": "domain",
    "IP_ADDRESS": "ip_address",
    "DNS": "dns",
    "URL": "url",
    "PHONE": "phone",
    "METADATA": "metadata",
    "REVERSE_IMAGE": "reverse_image",
    "FILE": "file",
    "SOCIAL_MEDIA": "social_media",
    "BREACH": "breach",
    "THREAT_INTELLIGENCE": "threat_intelligence",
    "MALWARE": "malware",
    "RISK_ASSESSMENT": "risk_assessment",
}


def upgrade() -> None:

    bind = op.get_bind()

    if bind.dialect.name == "postgresql":

        op.execute(
            "ALTER TABLE investigations "
            "ALTER COLUMN investigation_type TYPE VARCHAR(64) "
            "USING investigation_type::text"
        )

    # Normalize any uppercase-name rows to their lowercase application
    # value. Runs on every dialect - a no-op wherever rows are already
    # lowercase (the WHEN branches simply won't match).
    case_pairs = " ".join(
        f"WHEN '{name}' THEN '{value}'" for name, value in _NAME_TO_VALUE.items()
    )

    op.execute(
        f"""
        UPDATE investigations
        SET investigation_type = CASE investigation_type
            {case_pairs}
            ELSE investigation_type
        END
        """
    )

    if bind.dialect.name != "postgresql":

        # SQLite (and other non-Postgres dialects Alembic might target
        # in dev/test) never had a native enum type to alter away from -
        # ensure the column is at least declared as a plain string type
        # in the dialect's own metadata going forward.
        with op.batch_alter_table("investigations") as batch_op:
            batch_op.alter_column(
                "investigation_type",
                type_=sa.String(length=64),
                existing_nullable=False,
            )


def downgrade() -> None:
    """
    Downgrade schema.

    Recreating the native PostgreSQL enum type and converting the
    column back is possible but would resurrect the exact class of bug
    this migration exists to remove permanently. Consistent with this
    project's established convention of not providing a destructive/
    footgun-reintroducing automatic downgrade for enum-shape changes
    (see every prior investigation_type migration's downgrade()).
    """

    raise NotImplementedError(
        "Downgrading investigation_type back to a native PostgreSQL "
        "enum is not supported - it would reintroduce the enum name/"
        "value mismatch bug this migration fixes. Restore from a "
        "database backup taken before this migration if a downgrade "
        "is truly required."
    )
