"""add description to project

Revision ID: c61fd4859b33
Revises: c61fd4859b32
Create Date: 2025-10-01 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c61fd4859b33'
down_revision: Union[str, None] = 'c61fd4859b32'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('projects', sa.Column('description', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('projects', 'description')
