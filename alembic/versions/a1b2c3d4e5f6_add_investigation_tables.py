"""Add investigation tables

Revision ID: a1b2c3d4e5f6
Revises: d96d2ddaebeb
Create Date: 2026-07-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'd96d2ddaebeb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'investigations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column(
            'investigation_type',
            sa.Enum(
                'USERNAME', 'EMAIL', 'DOMAIN', 'IP_ADDRESS', 'DNS',
                'URL', 'PHONE', 'METADATA', 'REVERSE_IMAGE',
                name='investigationtype',
            ),
            nullable=False,
        ),
        sa.Column('target', sa.String(length=500), nullable=False),
        sa.Column(
            'status',
            sa.Enum(
                'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL',
                name='investigationstatus',
            ),
            nullable=False,
        ),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column(
            'risk_level',
            sa.Enum(
                'LOW', 'MEDIUM', 'HIGH', 'CRITICAL',
                name='risklevel',
            ),
            nullable=True,
        ),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_investigations_user_id'), 'investigations', ['user_id'], unique=False,
    )
    op.create_index(
        op.f('ix_investigations_investigation_type'), 'investigations', ['investigation_type'], unique=False,
    )
    op.create_index(
        op.f('ix_investigations_target'), 'investigations', ['target'], unique=False,
    )
    op.create_index(
        op.f('ix_investigations_status'), 'investigations', ['status'], unique=False,
    )
    op.create_index(
        'ix_investigations_user_created', 'investigations', ['user_id', 'created_at'], unique=False,
    )

    op.create_table(
        'investigation_results',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column(
            'status',
            sa.Enum(
                'SUCCESS', 'FAILED', 'NOT_FOUND', 'RATE_LIMITED', 'SKIPPED',
                name='moduleresultstatus',
            ),
            nullable=False,
        ),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.Column('raw_response', sa.JSON(), nullable=True),
        sa.Column('latency_ms', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['investigation_id'], ['investigations.id'], ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_investigation_results_investigation_id'),
        'investigation_results', ['investigation_id'], unique=False,
    )
    op.create_index(
        op.f('ix_investigation_results_source'),
        'investigation_results', ['source'], unique=False,
    )
    op.create_index(
        'ix_investigation_results_investigation_source',
        'investigation_results', ['investigation_id', 'source'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        'ix_investigation_results_investigation_source', table_name='investigation_results',
    )
    op.drop_index(
        op.f('ix_investigation_results_source'), table_name='investigation_results',
    )
    op.drop_index(
        op.f('ix_investigation_results_investigation_id'), table_name='investigation_results',
    )
    op.drop_table('investigation_results')

    op.drop_index('ix_investigations_user_created', table_name='investigations')
    op.drop_index(op.f('ix_investigations_status'), table_name='investigations')
    op.drop_index(op.f('ix_investigations_target'), table_name='investigations')
    op.drop_index(op.f('ix_investigations_investigation_type'), table_name='investigations')
    op.drop_index(op.f('ix_investigations_user_id'), table_name='investigations')
    op.drop_table('investigations')
