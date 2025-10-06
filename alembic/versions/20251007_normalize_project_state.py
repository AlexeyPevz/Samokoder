"""Normalize project state - create Epic, Task, Step, Iteration tables

Revision ID: 202510070001
Revises: None
Create Date: 2025-10-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '202510070001'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create normalized tables for Epic, Task, Step, and Iteration."""

    # Create epics table
    op.create_table(
        'epics',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_state_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('epic_index', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('source', sa.String(), nullable=True),
        sa.Column('complexity', sa.String(), nullable=True),
        sa.Column('user_review_goal', sa.String(), nullable=True),
        sa.Column('completed', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['project_state_id'], ['project_states.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_state_id', 'epic_index')
    )
    op.create_index('idx_epics_project_state_id', 'epics', ['project_state_id'], unique=False)
    op.create_index('idx_epics_name', 'epics', ['name'], unique=False)

    # Create tasks table
    op.create_table(
        'tasks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_state_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('epic_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('task_index', sa.Integer(), nullable=False),
        sa.Column('description', sa.String(), nullable=False),
        sa.Column('instructions', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='todo'),
        sa.Column('app_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('relevant_files', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['project_state_id'], ['project_states.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['epic_id'], ['epics.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_state_id', 'task_index')
    )
    op.create_index('idx_tasks_project_state_id', 'tasks', ['project_state_id'], unique=False)
    op.create_index('idx_tasks_epic_id', 'tasks', ['epic_id'], unique=False)
    op.create_index('idx_tasks_status', 'tasks', ['status'], unique=False)

    # Create steps table
    op.create_table(
        'steps',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_state_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('task_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('step_index', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('completed', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('save_file_path', sa.String(), nullable=True),
        sa.Column('command', sa.String(), nullable=True),
        sa.Column('command_id', sa.String(), nullable=True),
        sa.Column('timeout', sa.Integer(), nullable=True),
        sa.Column('check_if_fixed', sa.Boolean(), nullable=True),
        sa.Column('human_intervention_description', sa.String(), nullable=True),
        sa.Column('step_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['project_state_id'], ['project_states.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['task_id'], ['tasks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_state_id', 'step_index')
    )
    op.create_index('idx_steps_project_state_id', 'steps', ['project_state_id'], unique=False)
    op.create_index('idx_steps_task_id', 'steps', ['task_id'], unique=False)
    op.create_index('idx_steps_type', 'steps', ['type'], unique=False)
    op.create_index('idx_steps_completed', 'steps', ['completed'], unique=False)

    # Create iterations table
    op.create_table(
        'iterations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_state_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('iteration_index', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('bug_reproduction_description', sa.String(), nullable=True),
        sa.Column('user_feedback', sa.String(), nullable=True),
        sa.Column('command_id', sa.String(), nullable=True),
        sa.Column('alternative_solutions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('iteration_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['project_state_id'], ['project_states.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_state_id', 'iteration_index')
    )
    op.create_index('idx_iterations_project_state_id', 'iterations', ['project_state_id'], unique=False)
    op.create_index('idx_iterations_status', 'iterations', ['status'], unique=False)


def downgrade() -> None:
    """Drop normalized tables."""
    op.drop_index('idx_iterations_status', table_name='iterations')
    op.drop_index('idx_iterations_project_state_id', table_name='iterations')
    op.drop_table('iterations')

    op.drop_index('idx_steps_completed', table_name='steps')
    op.drop_index('idx_steps_type', table_name='steps')
    op.drop_index('idx_steps_task_id', table_name='steps')
    op.drop_index('idx_steps_project_state_id', table_name='steps')
    op.drop_table('steps')

    op.drop_index('idx_tasks_status', table_name='tasks')
    op.drop_index('idx_tasks_epic_id', table_name='tasks')
    op.drop_index('idx_tasks_project_state_id', table_name='tasks')
    op.drop_table('tasks')

    op.drop_index('idx_epics_name', table_name='epics')
    op.drop_index('idx_epics_project_state_id', table_name='epics')
    op.drop_table('epics')
