import os
os.environ['SECRET_KEY'] = 'your-super-secret-jwt-key-change-in-production-minimum-32-characters-for-security'
os.environ['APP_SECRET_KEY'] = 'your-super-secret-app-key-change-in-production-minimum-32-characters-for-security'

import tempfile
import os
from typing import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from alembic.config import Config
from alembic import command

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from samokoder.core.config.config import DatabaseConfig
from samokoder.core.db.models.base import Base
from samokoder.core.db.models.branch import Branch
from samokoder.core.db.models.exec_log import ExecLog
from samokoder.core.db.models.file_content import FileContent
from samokoder.core.db.models.file import File
from samokoder.core.db.models.llm_request import LLMRequest
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.project_state import ProjectState
from samokoder.core.db.models.specification import Specification
from samokoder.core.db.models.user_input import UserInput
from samokoder.core.db.models.user import User
from samokoder.core.db.session import SessionManager
from samokoder.core.db.migrations.utils import run_alembic_migrations
from samokoder.core.state.state_manager import StateManager






@pytest.fixture(autouse=True)
def disable_test_telemetry(monkeypatch):
    os.environ["DISABLE_TELEMETRY"] = "1"


@pytest.fixture(autouse=True, scope='session')
def change_test_dir(request):
    os.chdir(os.path.join(os.path.dirname(__file__), '..'))
    yield
    os.chdir(request.config.invocation_dir)


import asyncio

@pytest.fixture(scope="session")
def event_loop(request):
    """
    Create an instance of the default event loop for each test session.
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def testmanager():
    """
    Set up a temporary file-based SQLite database for testing.
    This ensures that all connections (sync and async) work with the same database.
    """
    # Create a temporary file for the SQLite database
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp_db_file:
        tmp_db_path = tmp_db_file.name

    db_cfg = DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_db_path}")
    os.environ["DATABASE_URL"] = db_cfg.url

    async_engine = create_async_engine(
        db_cfg.url,
        echo=db_cfg.debug_sql,
        connect_args={"check_same_thread": False}
    )

    sync_engine = create_engine(
        db_cfg.url.replace("sqlite+aiosqlite", "sqlite"),
        echo=db_cfg.debug_sql,
        connect_args={"check_same_thread": False}
    )

    manager = SessionManager(db_cfg)
    manager.async_engine = async_engine
    manager.AsyncSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=async_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    run_alembic_migrations(sync_engine)

    try:
        yield manager
    finally:
        sync_engine.dispose()
        await async_engine.dispose()
        os.remove(tmp_db_path) # Clean up the temporary database file





@pytest_asyncio.fixture(scope="function")
async def testdb(testmanager):
    """
    Set up a temporary in-memory database for testing.

    This fixture is an async context manager that yields
    a database session.
    """
    async with testmanager.AsyncSessionLocal() as session:
        await session.begin()  # Start a transaction
        yield session
        await session.rollback()  # Rollback after each test


from uuid import uuid4

@pytest_asyncio.fixture(scope="function")
async def test_user(testdb):
    user = User(
        email=f"test_{uuid4()}@example.com",
        hashed_password="password",
    )
    testdb.add(user)
    await testdb.commit()
    await testdb.refresh(user)
    return user


from fastapi.testclient import TestClient
from samokoder.api.main import app
from samokoder.core.db.session import get_async_db


@pytest.fixture(scope="function")
def client(testdb):
    app.dependency_overrides[get_async_db] = lambda: testdb
    original_cwd = os.getcwd()
    os.chdir(os.path.join(os.path.dirname(__file__), '..'))
    with TestClient(app) as c:
        yield c
    os.chdir(original_cwd)
    app.dependency_overrides = {}


@pytest_asyncio.fixture
async def agentcontext(testmanager, test_user):
    """
    Set up state manager, process manager, UI mock, and LLM mock for testing.

    Database and filesystem are in-memory.

    Yields the (state manager, process manager, UI mock, LLM mock) tuple.
    """
    with patch("core.state.state_manager.get_config") as mock_get_config:
        mock_get_config.return_value.fs.type = "memory"
        sm = StateManager(testmanager)
        pm = MagicMock()
        ui = MagicMock(
            send_project_stage=AsyncMock(),
            send_message=AsyncMock(),
            ask_question=AsyncMock(),
        )

        await sm.create_project("test", user_id=test_user.id)

        mock_llm = None

        def mock_get_llm(return_value=None, side_effect=None) -> Callable:
            """
            Returns a function that when called returns an async function
            that when awaited returns the given value, simulatng a LLM call.

            The mock LLM is created only once and reused for all calls in the test.

            :param return_value: The value to return when awaited (optional).
            :param side_effect: The side effect to apply when awaited (optional).
            :return: A function that returns the mocked LLM.
            """
            nonlocal mock_llm

            if not mock_llm:
                mock_llm = MagicMock(  # agent's get_llm() function
                    return_value=AsyncMock(  # the llm() async function
                        return_value=return_value,
                        side_effect=side_effect,
                    )
                )
            return mock_llm

        yield sm, pm, ui, mock_get_llm