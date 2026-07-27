"""Add image_fingerprints table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-25 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema.

    No InvestigationType enum change is needed here: REVERSE_IMAGE has
    been present in that enum since it was first defined, unlike FILE
    which the previous migration had to add.
    """

    op.create_table(
        'image_fingerprints',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('original_filename', sa.String(length=500), nullable=False),
        sa.Column('stored_filename', sa.String(length=255), nullable=False),
        sa.Column('storage_path', sa.String(length=1000), nullable=False),
        sa.Column('detected_mime_type', sa.String(length=255), nullable=True),
        sa.Column('file_size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('width', sa.Integer(), nullable=True),
        sa.Column('height', sa.Integer(), nullable=True),
        sa.Column('md5', sa.String(length=32), nullable=False),
        sa.Column('sha1', sa.String(length=40), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('phash', sa.String(length=64), nullable=True),
        sa.Column('ahash', sa.String(length=64), nullable=True),
        sa.Column('dhash', sa.String(length=64), nullable=True),
        sa.Column('extracted_metadata', sa.JSON(), nullable=True),
        sa.Column('uploaded_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['investigation_id'], ['investigations.id'], ondelete='CASCADE',
        ),
        sa.ForeignKeyConstraint(
            ['user_id'], ['users.id'], ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id'),
    )
    op.create_index(
        op.f('ix_image_fingerprints_investigation_id'), 'image_fingerprints', ['investigation_id'], unique=True,
    )
    op.create_index(
        op.f('ix_image_fingerprints_user_id'), 'image_fingerprints', ['user_id'], unique=False,
    )
    op.create_index(op.f('ix_image_fingerprints_md5'), 'image_fingerprints', ['md5'], unique=False)
    op.create_index(op.f('ix_image_fingerprints_sha256'), 'image_fingerprints', ['sha256'], unique=False)
    op.create_index(op.f('ix_image_fingerprints_phash'), 'image_fingerprints', ['phash'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_image_fingerprints_phash'), table_name='image_fingerprints')
    op.drop_index(op.f('ix_image_fingerprints_sha256'), table_name='image_fingerprints')
    op.drop_index(op.f('ix_image_fingerprints_md5'), table_name='image_fingerprints')
    op.drop_index(op.f('ix_image_fingerprints_user_id'), table_name='image_fingerprints')
    op.drop_index(op.f('ix_image_fingerprints_investigation_id'), table_name='image_fingerprints')
    op.drop_table('image_fingerprints')
