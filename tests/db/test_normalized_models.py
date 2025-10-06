"""Tests for normalized Epic, Task, Step, Iteration models."""
import os

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from samokoder.core.db.models import (
    Base,
    Branch,
    Epic,
    Iteration,
    Project,
    ProjectState,
    Specification,
    Step,
    Task,
    User,
)


@pytest_asyncio.fixture
async def async_session():
    """Create async session for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session_maker() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_epic_model_basic(async_session):
    """Test basic Epic model creation and retrieval."""
    # Create user, project, branch, specification
    user = User(email="test@example.com", hashed_password="hashed_pwd")
    async_session.add(user)
    await async_session.flush()

    project = Project(user_id=user.id, name="Test Project")
    async_session.add(project)
    await async_session.flush()

    branch = Branch(project_id=project.id, name="main")
    async_session.add(branch)
    await async_session.flush()

    spec = Specification(
        name="Test Spec",
        description="Test spec",
        architecture="MVC",
        system_dependencies=[],
        package_dependencies=[],
        templates=[]
    )
    async_session.add(spec)
    await async_session.flush()

    state = ProjectState(
        branch_id=branch.id,
        specification_id=spec.id
    )
    async_session.add(state)
    await async_session.flush()

    # Create Epic
    epic = Epic(
        project_state_id=state.id,
        epic_index=0,
        name="First Epic",
        description="Epic description",
        source="app",
        complexity="moderate"
    )
    async_session.add(epic)
    await async_session.commit()

    # Verify Epic
    assert epic.id is not None
    assert epic.name == "First Epic"
    assert epic.epic_index == 0
    assert epic.completed is False

    # Test to_dict
    epic_dict = epic.to_dict()
    assert epic_dict["name"] == "First Epic"
    assert epic_dict["source"] == "app"
    assert epic_dict["completed"] is False


@pytest.mark.asyncio
async def test_task_model_with_epic(async_session):
    """Test Task model with Epic relationship."""
    # Setup
    user = User(email="test@example.com", hashed_password="hashed_pwd")
    async_session.add(user)
    await async_session.flush()

    project = Project(user_id=user.id, name="Test Project")
    async_session.add(project)
    await async_session.flush()

    branch = Branch(project_id=project.id, name="main")
    async_session.add(branch)
    await async_session.flush()

    spec = Specification(name="Test Spec", description="Test", architecture="MVC", system_dependencies=[], package_dependencies=[], templates=[])
    async_session.add(spec)
    await async_session.flush()

    state = ProjectState(branch_id=branch.id, specification_id=spec.id)
    async_session.add(state)
    await async_session.flush()

    epic = Epic(
        project_state_id=state.id,
        epic_index=0,
        name="Epic 1"
    )
    async_session.add(epic)
    await async_session.flush()

    # Create Task
    task = Task(
        project_state_id=state.id,
        epic_id=epic.id,
        task_index=0,
        description="Implement feature X",
        instructions="Do this and that",
        status="in_progress"
    )
    async_session.add(task)
    await async_session.commit()

    # Verify
    assert task.id is not None
    assert task.description == "Implement feature X"
    assert task.status == "in_progress"
    assert task.epic_id == epic.id

    # Test to_dict
    task_dict = task.to_dict()
    assert task_dict["description"] == "Implement feature X"
    assert task_dict["status"] == "in_progress"
    assert task_dict["instructions"] == "Do this and that"


@pytest.mark.asyncio
async def test_step_model_save_file_type(async_session):
    """Test Step model with save_file type."""
    # Setup
    user = User(email="test@example.com", hashed_password="hashed_pwd")
    async_session.add(user)
    await async_session.flush()

    project = Project(user_id=user.id, name="Test Project")
    async_session.add(project)
    await async_session.flush()

    branch = Branch(project_id=project.id, name="main")
    async_session.add(branch)
    await async_session.flush()

    spec = Specification(name="Test Spec", description="Test", architecture="MVC", system_dependencies=[], package_dependencies=[], templates=[])
    async_session.add(spec)
    await async_session.flush()

    state = ProjectState(branch_id=branch.id, specification_id=spec.id)
    async_session.add(state)
    await async_session.flush()

    task = Task(
        project_state_id=state.id,
        task_index=0,
        description="Task 1"
    )
    async_session.add(task)
    await async_session.flush()

    # Create Step
    step = Step(
        project_state_id=state.id,
        task_id=task.id,
        step_index=0,
        type="save_file",
        save_file_path="/path/to/file.py"
    )
    async_session.add(step)
    await async_session.commit()

    # Verify
    assert step.id is not None
    assert step.type == "save_file"
    assert step.save_file_path == "/path/to/file.py"
    assert step.completed is False

    # Test to_dict
    step_dict = step.to_dict()
    assert step_dict["type"] == "save_file"
    assert step_dict["save_file"]["path"] == "/path/to/file.py"
    assert step_dict["completed"] is False


@pytest.mark.asyncio
async def test_iteration_model_basic(async_session):
    """Test basic Iteration model."""
    # Setup
    user = User(email="test@example.com", hashed_password="hashed_pwd")
    async_session.add(user)
    await async_session.flush()

    project = Project(user_id=user.id, name="Test Project")
    async_session.add(project)
    await async_session.flush()

    branch = Branch(project_id=project.id, name="main")
    async_session.add(branch)
    await async_session.flush()

    spec = Specification(name="Test Spec", description="Test", architecture="MVC", system_dependencies=[], package_dependencies=[], templates=[])
    async_session.add(spec)
    await async_session.flush()

    state = ProjectState(branch_id=branch.id, specification_id=spec.id)
    async_session.add(state)
    await async_session.flush()

    # Create Iteration
    iteration = Iteration(
        project_state_id=state.id,
        iteration_index=0,
        status="check_logs",
        description="Debugging iteration",
        bug_reproduction_description="Bug occurs when...",
        alternative_solutions=[
            {"tried": True, "solution": "Solution 1"},
            {"tried": False, "solution": "Solution 2"}
        ]
    )
    async_session.add(iteration)
    await async_session.commit()

    # Verify
    assert iteration.id is not None
    assert iteration.status == "check_logs"
    assert iteration.description == "Debugging iteration"
    assert len(iteration.alternative_solutions) == 2

    # Test to_dict
    iteration_dict = iteration.to_dict()
    assert iteration_dict["status"] == "check_logs"
    assert iteration_dict["description"] == "Debugging iteration"
    assert len(iteration_dict["alternative_solutions"]) == 2


@pytest.mark.asyncio
async def test_cascade_delete(async_session):
    """Test that deleting ProjectState cascades to normalized models."""
    # Setup
    user = User(email="test@example.com", hashed_password="hashed_pwd")
    async_session.add(user)
    await async_session.flush()

    project = Project(user_id=user.id, name="Test Project")
    async_session.add(project)
    await async_session.flush()

    branch = Branch(project_id=project.id, name="main")
    async_session.add(branch)
    await async_session.flush()

    spec = Specification(name="Test Spec", description="Test", architecture="MVC", system_dependencies=[], package_dependencies=[], templates=[])
    async_session.add(spec)
    await async_session.flush()

    state = ProjectState(branch_id=branch.id, specification_id=spec.id)
    async_session.add(state)
    await async_session.flush()

    # Create related entities
    epic = Epic(project_state_id=state.id, epic_index=0, name="Epic")
    async_session.add(epic)
    await async_session.flush()

    task = Task(project_state_id=state.id, task_index=0, description="Task")
    async_session.add(task)
    await async_session.flush()

    step = Step(project_state_id=state.id, step_index=0, type="command")
    async_session.add(step)
    await async_session.flush()

    iteration = Iteration(project_state_id=state.id, iteration_index=0, status="done")
    async_session.add(iteration)
    await async_session.commit()

    state_id = state.id
    epic_id = epic.id
    task_id = task.id
    step_id = step.id
    iteration_id = iteration.id

    # Delete state
    await async_session.delete(state)
    await async_session.commit()

    # Verify cascade delete
    from sqlalchemy import select

    epic_check = await async_session.execute(select(Epic).where(Epic.id == epic_id))
    assert epic_check.scalar_one_or_none() is None

    task_check = await async_session.execute(select(Task).where(Task.id == task_id))
    assert task_check.scalar_one_or_none() is None

    step_check = await async_session.execute(select(Step).where(Step.id == step_id))
    assert step_check.scalar_one_or_none() is None

    iteration_check = await async_session.execute(select(Iteration).where(Iteration.id == iteration_id))
    assert iteration_check.scalar_one_or_none() is None


def test_normalize_migration_exists():
    """Test that normalization migration exists and has correct structure."""
    migration_file = os.path.join(
        os.path.dirname(__file__),
        '../../alembic/versions/20251007_normalize_project_state.py'
    )

    assert os.path.exists(migration_file), "Migration file not found"

    with open(migration_file, 'r') as f:
        content = f.read()

    # Verify revision IDs
    assert "revision: str = '202510070001'" in content
    assert "down_revision: Union[str, Sequence[str], None] = None" in content

    # Verify tables are created
    assert "create_table" in content and "epics" in content
    assert "create_table" in content and "tasks" in content
    assert "create_table" in content and "steps" in content
    assert "create_table" in content and "iterations" in content

    # Verify indexes
    assert "idx_epics_project_state_id" in content
    assert "idx_tasks_project_state_id" in content
    assert "idx_steps_project_state_id" in content
    assert "idx_iterations_project_state_id" in content

    # Verify downgrade drops tables
    assert "drop_table" in content and "epics" in content
    assert "drop_table" in content and "tasks" in content
    assert "drop_table" in content and "steps" in content
    assert "drop_table" in content and "iterations" in content
