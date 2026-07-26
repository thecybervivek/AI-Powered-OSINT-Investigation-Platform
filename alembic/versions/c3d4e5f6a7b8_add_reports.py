"""Add reports table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-25 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    bind = op.get_bind()

    # New enum types introduced by Milestone 7.
    report_status_enum = postgresql.ENUM(
        "GENERATING",
        "COMPLETED",
        "FAILED",
        name="reportstatus",
        create_type=False,
    )

    ai_engine_enum = postgresql.ENUM(
        "OPENAI",
        "LOCAL_DETERMINISTIC",
        name="aiengineused",
        create_type=False,
    )

    # Existing enum introduced by an earlier milestone.
    # Reuse it instead of attempting CREATE TYPE again.
    risk_level_enum = postgresql.ENUM(
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        name="risklevel",
        create_type=False,
    )

    # Create only the new Milestone 7 enum types.
    report_status_enum.create(bind, checkfirst=True)
    ai_engine_enum.create(bind, checkfirst=True)

    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("investigation_ids", sa.JSON(), nullable=False),
        sa.Column(
            "status",
            report_status_enum,
            nullable=False,
        ),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("technical_summary", sa.Text(), nullable=True),
        sa.Column("investigation_summary", sa.Text(), nullable=True),
        sa.Column("threat_analysis", sa.Text(), nullable=True),
        sa.Column("risk_explanation", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column(
            "risk_level",
            risk_level_enum,
            nullable=True,
        ),
        sa.Column("indicators_of_compromise", sa.JSON(), nullable=True),
        sa.Column("evidence_timeline", sa.JSON(), nullable=True),
        sa.Column("evidence_correlation", sa.JSON(), nullable=True),
        sa.Column("ai_recommendations", sa.JSON(), nullable=True),
        sa.Column("mitre_attack_mapping", sa.JSON(), nullable=True),
        sa.Column("investigation_metadata", sa.JSON(), nullable=True),
        sa.Column(
            "ai_engine_used",
            ai_engine_enum,
            nullable=True,
        ),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        op.f("ix_reports_user_id"),
        "reports",
        ["user_id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_reports_status"),
        "reports",
        ["status"],
        unique=False,
    )

    op.create_index(
        "ix_reports_user_created",
        "reports",
        ["user_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""

    bind = op.get_bind()

    op.drop_index(
        "ix_reports_user_created",
        table_name="reports",
    )

    op.drop_index(
        op.f("ix_reports_status"),
        table_name="reports",
    )

    op.drop_index(
        op.f("ix_reports_user_id"),
        table_name="reports",
    )

    op.drop_table("reports")

    # Remove only enum types owned by this migration.
    postgresql.ENUM(
        name="reportstatus",
        create_type=False,
    ).drop(bind, checkfirst=True)

    postgresql.ENUM(
        name="aiengineused",
        create_type=False,
    ).drop(bind, checkfirst=True)

    # DO NOT drop risklevel.
    # It belongs to an earlier milestone and may still be used elsewhere.