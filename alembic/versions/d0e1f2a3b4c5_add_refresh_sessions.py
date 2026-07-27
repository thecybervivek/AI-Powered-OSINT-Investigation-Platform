"""Add server-tracked refresh sessions.

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
"""
from alembic import op
import sqlalchemy as sa
revision='d0e1f2a3b4c5'; down_revision='c9d0e1f2a3b4'; branch_labels=None; depends_on=None

def upgrade():
    op.create_table('refresh_sessions',
        sa.Column('id',sa.String(36),primary_key=True), sa.Column('user_id',sa.String(36),sa.ForeignKey('users.id',ondelete='CASCADE'),nullable=False),
        sa.Column('jti_hash',sa.String(64),nullable=False), sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('revoked',sa.Boolean(),nullable=False,server_default=sa.false()), sa.Column('replaced_by_jti_hash',sa.String(64),nullable=True),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False), sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False))
    op.create_index('ix_refresh_sessions_user_id','refresh_sessions',['user_id']); op.create_index('ix_refresh_sessions_jti_hash','refresh_sessions',['jti_hash'],unique=True)
def downgrade(): op.drop_table('refresh_sessions')
