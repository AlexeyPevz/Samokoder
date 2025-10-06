"""Add is_admin field to users table

Revision ID: 2025_10_06_add_is_admin
Revises: 
Create Date: 2025-10-06

P0-1: Add is_admin boolean field for admin role checking
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2025_10_06_add_is_admin'
down_revision = None  # Update this with your latest migration ID
branch_labels = None
depends_on = None


def upgrade():
    """Add is_admin field to users table."""
    # Add is_admin column with default False
    op.add_column('users', sa.Column('is_admin', sa.Boolean(), nullable=False, server_default='0'))


def downgrade():
    """Remove is_admin field from users table."""
    op.drop_column('users', 'is_admin')
