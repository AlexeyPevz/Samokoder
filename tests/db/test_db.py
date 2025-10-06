import pytest
from sqlalchemy import func, select

from samokoder.core.db.models import Project, ProjectState

from .factories import create_project_state


@pytest.mark.asyncio
async def test_select_empty(testdb):
    q = await testdb.execute(select(func.count()).select_from(Project))
    count = q.scalar_one()
    assert count == 0


@pytest.mark.asyncio
async def test_create_select_project_branch_state(testdb, test_user):
    state = create_project_state(user=test_user)
    state.tasks = [{"id": "test", "name": "test task"}]

    testdb.add(state)
    await testdb.commit()

    q = await testdb.execute(select(func.count()).select_from(Project))
    count = q.scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_deleting_project_state_clears_back_references(testdb, test_user):
    state1 = create_project_state(user=test_user)
    testdb.add(state1)
    await testdb.commit()

    state2 = await state1.create_next_state()
    testdb.add(state2)
    await testdb.commit()

    # Check that both project states were added correctly
    q = await testdb.execute(select(ProjectState).where(ProjectState.id == state2.id))
    result = q.scalar_one()

    assert result == state2
    assert result.prev_state == state1

    # Delete the first one
    await testdb.delete(state1)
    await testdb.commit()

    # Check the second one still exists and has no back reference
    await testdb.refresh(state2, attribute_names=["prev_state"])

    # After adding lazy="raise" to the the prev_state relationship,
    # this assertion would fail with an ORM exception, *unless* we add
    # the prev_state in the attribute_names in the above `refresh()`,
    # which then causes SQLAlchemy to explicitly load that relationship
    # Alternative is to just assert `prev_state_id is None`, which works
    # without the attribute_names
    assert state2.prev_state is None
