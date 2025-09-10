"""Add audit fields and soft delete support

Revision ID: 20250910_audit
Revises: 20250910_performance
Create Date: 2025-09-10 15:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '20250910_audit'
down_revision: Union[str, Sequence[str], None] = '20250910_performance'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add audit fields and soft delete support."""
    
    # Add soft delete fields to projects table
    op.add_column('projects', sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('projects', sa.Column('deleted_by', sa.UUID(), nullable=True))
    
    # Add soft delete fields to chat_sessions table
    op.add_column('chat_sessions', sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('chat_sessions', sa.Column('deleted_by', sa.UUID(), nullable=True))
    
    # Add soft delete fields to files table
    op.add_column('files', sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('files', sa.Column('deleted_by', sa.UUID(), nullable=True))
    
    # Add audit fields to profiles table
    op.add_column('profiles', sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('profiles', sa.Column('login_count', sa.Integer(), nullable=True, server_default=sa.text('0')))
    op.add_column('profiles', sa.Column('is_deleted', sa.Boolean(), nullable=True, server_default=sa.text('false')))
    op.add_column('profiles', sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True))
    
    # Add version field to projects for optimistic locking
    op.add_column('projects', sa.Column('version', sa.Integer(), nullable=True, server_default=sa.text('1')))
    
    # Add metadata fields to projects
    op.add_column('projects', sa.Column('metadata', sa.JSON(), nullable=True))
    op.add_column('projects', sa.Column('tags', sa.ARRAY(sa.String()), nullable=True))
    
    # Add file metadata
    op.add_column('files', sa.Column('metadata', sa.JSON(), nullable=True))
    op.add_column('files', sa.Column('checksum', sa.String(), nullable=True))
    op.add_column('files', sa.Column('mime_type', sa.String(), nullable=True))
    
    # Add session metadata
    op.add_column('chat_sessions', sa.Column('metadata', sa.JSON(), nullable=True))
    op.add_column('chat_sessions', sa.Column('message_count', sa.Integer(), nullable=True, server_default=sa.text('0')))
    
    # Add message metadata
    op.add_column('chat_messages', sa.Column('tokens_used', sa.Integer(), nullable=True))
    op.add_column('chat_messages', sa.Column('model_used', sa.String(), nullable=True))
    op.add_column('chat_messages', sa.Column('processing_time_ms', sa.Integer(), nullable=True))
    
    # Add indexes for new fields
    op.create_index('idx_projects_deleted_at', 'projects', ['deleted_at'])
    op.create_index('idx_projects_version', 'projects', ['version'])
    op.create_index('idx_projects_tags', 'projects', ['tags'], postgresql_using='gin')
    
    op.create_index('idx_chat_sessions_deleted_at', 'chat_sessions', ['deleted_at'])
    op.create_index('idx_chat_sessions_message_count', 'chat_sessions', ['message_count'])
    
    op.create_index('idx_files_deleted_at', 'files', ['deleted_at'])
    op.create_index('idx_files_checksum', 'files', ['checksum'])
    op.create_index('idx_files_mime_type', 'files', ['mime_type'])
    
    op.create_index('idx_profiles_last_login', 'profiles', ['last_login_at'])
    op.create_index('idx_profiles_is_deleted', 'profiles', ['is_deleted'])
    op.create_index('idx_profiles_deleted_at', 'profiles', ['deleted_at'])
    
    op.create_index('idx_chat_messages_tokens', 'chat_messages', ['tokens_used'])
    op.create_index('idx_chat_messages_model', 'chat_messages', ['model_used'])
    
    # Add constraints for new fields
    op.create_check_constraint(
        'ck_profiles_login_count_positive',
        'profiles',
        "login_count IS NULL OR login_count >= 0"
    )
    
    op.create_check_constraint(
        'ck_projects_version_positive',
        'projects',
        "version IS NULL OR version >= 1"
    )
    
    op.create_check_constraint(
        'ck_chat_sessions_message_count_positive',
        'chat_sessions',
        "message_count IS NULL OR message_count >= 0"
    )
    
    op.create_check_constraint(
        'ck_chat_messages_tokens_positive',
        'chat_messages',
        "tokens_used IS NULL OR tokens_used >= 0"
    )
    
    op.create_check_constraint(
        'ck_chat_messages_processing_time_positive',
        'chat_messages',
        "processing_time_ms IS NULL OR processing_time_ms >= 0"
    )


def downgrade() -> None:
    """Remove audit fields and soft delete support."""
    
    # Drop constraints
    op.drop_constraint('ck_chat_messages_processing_time_positive', 'chat_messages')
    op.drop_constraint('ck_chat_messages_tokens_positive', 'chat_messages')
    op.drop_constraint('ck_chat_sessions_message_count_positive', 'chat_sessions')
    op.drop_constraint('ck_projects_version_positive', 'projects')
    op.drop_constraint('ck_profiles_login_count_positive', 'profiles')
    
    # Drop indexes
    op.drop_index('idx_chat_messages_model', 'chat_messages')
    op.drop_index('idx_chat_messages_tokens', 'chat_messages')
    op.drop_index('idx_profiles_deleted_at', 'profiles')
    op.drop_index('idx_profiles_is_deleted', 'profiles')
    op.drop_index('idx_profiles_last_login', 'profiles')
    op.drop_index('idx_files_mime_type', 'files')
    op.drop_index('idx_files_checksum', 'files')
    op.drop_index('idx_files_deleted_at', 'files')
    op.drop_index('idx_chat_sessions_message_count', 'chat_sessions')
    op.drop_index('idx_chat_sessions_deleted_at', 'chat_sessions')
    op.drop_index('idx_projects_tags', 'projects')
    op.drop_index('idx_projects_version', 'projects')
    op.drop_index('idx_projects_deleted_at', 'projects')
    
    # Drop columns
    op.drop_column('chat_messages', 'processing_time_ms')
    op.drop_column('chat_messages', 'model_used')
    op.drop_column('chat_messages', 'tokens_used')
    
    op.drop_column('chat_sessions', 'message_count')
    op.drop_column('chat_sessions', 'metadata')
    
    op.drop_column('files', 'mime_type')
    op.drop_column('files', 'checksum')
    op.drop_column('files', 'metadata')
    op.drop_column('files', 'deleted_by')
    op.drop_column('files', 'deleted_at')
    
    op.drop_column('projects', 'tags')
    op.drop_column('projects', 'metadata')
    op.drop_column('projects', 'version')
    op.drop_column('projects', 'deleted_by')
    op.drop_column('projects', 'deleted_at')
    
    op.drop_column('profiles', 'deleted_at')
    op.drop_column('profiles', 'is_deleted')
    op.drop_column('profiles', 'login_count')
    op.drop_column('profiles', 'last_login_at')
    
    op.drop_column('chat_sessions', 'deleted_by')
    op.drop_column('chat_sessions', 'deleted_at')