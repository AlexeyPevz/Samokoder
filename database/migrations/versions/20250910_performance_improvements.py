"""Add indexes and constraints for performance

Revision ID: 20250910_performance
Revises: 9571625a63ee
Create Date: 2025-09-10 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '20250910_performance'
down_revision: Union[str, Sequence[str], None] = '9571625a63ee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add performance improvements."""
    
    # Add indexes for frequently queried columns
    op.create_index('idx_profiles_email', 'profiles', ['email'])
    op.create_index('idx_profiles_created_at', 'profiles', ['created_at'])
    
    op.create_index('idx_projects_user_id', 'projects', ['user_id'])
    op.create_index('idx_projects_created_at', 'projects', ['created_at'])
    op.create_index('idx_projects_is_active', 'projects', ['is_active'])
    
    op.create_index('idx_chat_sessions_project_id', 'chat_sessions', ['project_id'])
    op.create_index('idx_chat_sessions_user_id', 'chat_sessions', ['user_id'])
    op.create_index('idx_chat_sessions_created_at', 'chat_sessions', ['created_at'])
    
    op.create_index('idx_chat_messages_session_id', 'chat_messages', ['session_id'])
    op.create_index('idx_chat_messages_created_at', 'chat_messages', ['created_at'])
    op.create_index('idx_chat_messages_role', 'chat_messages', ['role'])
    
    op.create_index('idx_api_keys_user_id', 'api_keys', ['user_id'])
    op.create_index('idx_api_keys_provider', 'api_keys', ['provider'])
    op.create_index('idx_api_keys_is_active', 'api_keys', ['is_active'])
    
    op.create_index('idx_files_project_id', 'files', ['project_id'])
    op.create_index('idx_files_user_id', 'files', ['user_id'])
    op.create_index('idx_files_path', 'files', ['path'])
    
    op.create_index('idx_ai_usage_user_id', 'ai_usage', ['user_id'])
    op.create_index('idx_ai_usage_project_id', 'ai_usage', ['project_id'])
    op.create_index('idx_ai_usage_provider', 'ai_usage', ['provider'])
    op.create_index('idx_ai_usage_created_at', 'ai_usage', ['created_at'])
    
    # Add composite indexes for common query patterns
    op.create_index('idx_projects_user_active', 'projects', ['user_id', 'is_active'])
    op.create_index('idx_chat_sessions_project_user', 'chat_sessions', ['project_id', 'user_id'])
    op.create_index('idx_files_project_path', 'files', ['project_id', 'path'])
    op.create_index('idx_ai_usage_user_created', 'ai_usage', ['user_id', 'created_at'])
    
    # Add partial indexes for active records
    op.create_index('idx_projects_active', 'projects', ['user_id'], 
                   postgresql_where=sa.text('is_active = true'))
    op.create_index('idx_api_keys_active', 'api_keys', ['user_id', 'provider'], 
                   postgresql_where=sa.text('is_active = true'))
    
    # Add constraints for data integrity
    op.create_check_constraint(
        'ck_profiles_email_format',
        'profiles',
        "email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'"
    )
    
    op.create_check_constraint(
        'ck_projects_name_length',
        'projects',
        "char_length(name) >= 1 AND char_length(name) <= 255"
    )
    
    op.create_check_constraint(
        'ck_chat_messages_content_length',
        'chat_messages',
        "char_length(content) >= 1 AND char_length(content) <= 50000"
    )
    
    op.create_check_constraint(
        'ck_files_name_length',
        'files',
        "char_length(name) >= 1 AND char_length(name) <= 255"
    )
    
    op.create_check_constraint(
        'ck_ai_usage_tokens_positive',
        'ai_usage',
        "tokens_used IS NULL OR tokens_used >= 0"
    )
    
    op.create_check_constraint(
        'ck_ai_usage_cost_positive',
        'ai_usage',
        "cost IS NULL OR cost >= 0"
    )


def downgrade() -> None:
    """Remove performance improvements."""
    
    # Drop constraints
    op.drop_constraint('ck_ai_usage_cost_positive', 'ai_usage')
    op.drop_constraint('ck_ai_usage_tokens_positive', 'ai_usage')
    op.drop_constraint('ck_files_name_length', 'files')
    op.drop_constraint('ck_chat_messages_content_length', 'chat_messages')
    op.drop_constraint('ck_projects_name_length', 'projects')
    op.drop_constraint('ck_profiles_email_format', 'profiles')
    
    # Drop partial indexes
    op.drop_index('idx_api_keys_active', 'api_keys')
    op.drop_index('idx_projects_active', 'projects')
    
    # Drop composite indexes
    op.drop_index('idx_ai_usage_user_created', 'ai_usage')
    op.drop_index('idx_files_project_path', 'files')
    op.drop_index('idx_chat_sessions_project_user', 'chat_sessions')
    op.drop_index('idx_projects_user_active', 'projects')
    
    # Drop single column indexes
    op.drop_index('idx_ai_usage_created_at', 'ai_usage')
    op.drop_index('idx_ai_usage_provider', 'ai_usage')
    op.drop_index('idx_ai_usage_project_id', 'ai_usage')
    op.drop_index('idx_ai_usage_user_id', 'ai_usage')
    
    op.drop_index('idx_files_path', 'files')
    op.drop_index('idx_files_user_id', 'files')
    op.drop_index('idx_files_project_id', 'files')
    
    op.drop_index('idx_api_keys_is_active', 'api_keys')
    op.drop_index('idx_api_keys_provider', 'api_keys')
    op.drop_index('idx_api_keys_user_id', 'api_keys')
    
    op.drop_index('idx_chat_messages_role', 'chat_messages')
    op.drop_index('idx_chat_messages_created_at', 'chat_messages')
    op.drop_index('idx_chat_messages_session_id', 'chat_messages')
    
    op.drop_index('idx_chat_sessions_created_at', 'chat_sessions')
    op.drop_index('idx_chat_sessions_user_id', 'chat_sessions')
    op.drop_index('idx_chat_sessions_project_id', 'chat_sessions')
    
    op.drop_index('idx_projects_is_active', 'projects')
    op.drop_index('idx_projects_created_at', 'projects')
    op.drop_index('idx_projects_user_id', 'projects')
    
    op.drop_index('idx_profiles_created_at', 'profiles')
    op.drop_index('idx_profiles_email', 'profiles')