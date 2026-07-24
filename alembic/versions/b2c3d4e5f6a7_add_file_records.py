"""Add file_records table and FILE investigation type

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()

    if bind.dialect.name == 'postgresql':
        # Postgres enums can't be extended inside a transaction block on
        # older server versions, so this runs on an autocommit connection.
        # No-op on SQLite/other dialects, where SQLAlchemy's Enum type
        # is just a VARCHAR + CHECK constraint recreated from the model.
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE investigationtype ADD VALUE IF NOT EXISTS 'file'")

    op.create_table(
        'file_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('original_filename', sa.String(length=500), nullable=False),
        sa.Column('stored_filename', sa.String(length=255), nullable=False),
        sa.Column('storage_path', sa.String(length=1000), nullable=False),
        sa.Column('declared_extension', sa.String(length=50), nullable=True),
        sa.Column('detected_mime_type', sa.String(length=255), nullable=True),
        sa.Column('file_size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('md5', sa.String(length=32), nullable=False),
        sa.Column('sha1', sa.String(length=40), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('extracted_metadata', sa.JSON(), nullable=True),
        sa.Column('timeline', sa.JSON(), nullable=True),
        sa.Column('uploaded_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['investigation_id'], ['investigations.id'], ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id'),
    )
    op.create_index(
        op.f('ix_file_records_investigation_id'), 'file_records', ['investigation_id'], unique=True,
    )
    op.create_index(op.f('ix_file_records_md5'), 'file_records', ['md5'], unique=False)
    op.create_index(op.f('ix_file_records_sha1'), 'file_records', ['sha1'], unique=False)
    op.create_index(op.f('ix_file_records_sha256'), 'file_records', ['sha256'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_file_records_sha256'), table_name='file_records')
    op.drop_index(op.f('ix_file_records_sha1'), table_name='file_records')
    op.drop_index(op.f('ix_file_records_md5'), table_name='file_records')
    op.drop_index(op.f('ix_file_records_investigation_id'), table_name='file_records')
    op.drop_table('file_records')

    # Postgres does not support removing a single enum value; downgrading
    # past this migration on Postgres requires recreating the enum type
    # manually if the 'file' value must be fully removed.
