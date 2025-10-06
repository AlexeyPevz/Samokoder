"""Add security tables for token revocation and login attempts tracking.

Revision ID: sec_001
Revises: 
Create Date: 2025-10-06

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'sec_001'
down_revision = None  # Update this to latest migration
branch_labels = None
depends_on = None


def upgrade():
    # Create revoked_tokens table for JWT revocation (P1-1)
    op.create_table(
        'revoked_tokens',
        sa.Column('jti', sa.String(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=False),
        sa.Column('reason', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('jti')
    )
    op.create_index('ix_revoked_tokens_jti', 'revoked_tokens', ['jti'])
    op.create_index('ix_revoked_tokens_expires_at', 'revoked_tokens', ['expires_at'])
    
    # Create login_attempts table for brute force protection (P1-3)
    op.create_table(
        'login_attempts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('ip_address', sa.String(), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('user_agent', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_login_attempts_email', 'login_attempts', ['email'])
    op.create_index('ix_login_attempts_created_at', 'login_attempts', ['created_at'])
    op.create_index('ix_login_attempts_success', 'login_attempts', ['success'])


def downgrade():
    op.drop_index('ix_login_attempts_success', table_name='login_attempts')
    op.drop_index('ix_login_attempts_created_at', table_name='login_attempts')
    op.drop_index('ix_login_attempts_email', table_name='login_attempts')
    op.drop_table('login_attempts')
    
    op.drop_index('ix_revoked_tokens_expires_at', table_name='revoked_tokens')
    op.drop_index('ix_revoked_tokens_jti', table_name='revoked_tokens')
    op.drop_table('revoked_tokens')
