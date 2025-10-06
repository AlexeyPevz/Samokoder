"""Add performance indexes

Revision ID: add_performance_indexes
Revises: 20251007_normalize_project_state
Create Date: 2025-10-06 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_performance_indexes'
down_revision = '20251007_normalize_project_state'
branch_labels = None
depends_on = None


def upgrade():
    """Add missing indexes for foreign keys and common queries."""
    # Foreign key indexes
    op.create_index('idx_projects_user_id', 'projects', ['user_id'])
    op.create_index('idx_files_project_id', 'files', ['project_id'])
    op.create_index('idx_llm_requests_project_id', 'llm_requests', ['project_id'])
    op.create_index('idx_llm_requests_user_id', 'llm_requests', ['user_id'])
    
    # Query optimization indexes
    op.create_index('idx_llm_requests_created_at', 'llm_requests', ['created_at'])
    op.create_index('idx_projects_created_at', 'projects', ['created_at'])
    op.create_index('idx_projects_status', 'projects', ['status'])
    
    # Composite indexes for common queries
    op.create_index(
        'idx_llm_requests_provider_model_created', 
        'llm_requests', 
        ['provider', 'model', 'created_at']
    )
    
    # Partial index for active projects
    op.execute("""
        CREATE INDEX idx_projects_active 
        ON projects(user_id, created_at) 
        WHERE status NOT IN ('completed', 'failed', 'cancelled')
    """)


def downgrade():
    """Remove performance indexes."""
    op.drop_index('idx_projects_user_id', 'projects')
    op.drop_index('idx_files_project_id', 'files')
    op.drop_index('idx_llm_requests_project_id', 'llm_requests')
    op.drop_index('idx_llm_requests_user_id', 'llm_requests')
    op.drop_index('idx_llm_requests_created_at', 'llm_requests')
    op.drop_index('idx_projects_created_at', 'projects')
    op.drop_index('idx_projects_status', 'projects')
    op.drop_index('idx_llm_requests_provider_model_created', 'llm_requests')
    op.drop_index('idx_projects_active', 'projects')