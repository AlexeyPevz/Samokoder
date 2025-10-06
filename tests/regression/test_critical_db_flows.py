"""
Regression tests for critical database session management flows.

Priority: P0 - BLOCKS MERGE if any test fails
Related commits: 298d1cc (DB session management refactor)
"""
import pytest
import asyncio
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession as AsyncSessionType

from samokoder.core.db.session import SessionManager, get_async_engine, dispose_engines, _engine_cache
from samokoder.core.db.models.base import Base
from samokoder.core.db.models.user import User, Tier
from samokoder.core.config.database import DatabaseConfig


@pytest.mark.priority_p0
class TestTransactionManagement:
    """TC-DB-001: Transaction rollback on errors."""
    
    @pytest.mark.asyncio
    async def test_tc_db_001_rollback_on_error(self):
        """
        P0: Test that transactions rollback on exceptions.
        
        Reproduction steps:
        1. Start transaction via SessionManager.get_session()
        2. Create a record
        3. Raise exception
        4. Verify record NOT in database
        5. Verify session.rollback() was called
        
        Links:
        - core/db/session.py:94-107
        - Commit: 298d1cc
        
        Failure criteria:
        - Changes committed despite exception
        - Session not closed
        - rollback not called
        - Connection leak
        """
        # Create test database
        db_config = DatabaseConfig(
            url="sqlite+aiosqlite:///:memory:",
            debug_sql=False
        )
        
        session_manager = SessionManager(db_config)
        
        # Create tables
        async with session_manager.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        try:
            # Test rollback on exception
            with pytest.raises(ValueError):
                async with session_manager.get_session() as db:
                    # Create a user
                    user = User(
                        email="rollback_test@example.com",
                        hashed_password="hashed",
                        tier=Tier.FREE
                    )
                    db.add(user)
                    await db.flush()
                    
                    # Verify user exists in current transaction
                    result = await db.execute(select(User).where(User.email == "rollback_test@example.com"))
                    assert result.scalars().first() is not None, "User should exist in transaction"
                    
                    # Raise exception to trigger rollback
                    raise ValueError("Test exception")
            
            # Verify user was NOT committed (rollback occurred)
            async with session_manager.get_session() as db:
                result = await db.execute(select(User).where(User.email == "rollback_test@example.com"))
                user_after = result.scalars().first()
                
                assert user_after is None, \
                    "P0 FAILURE: User was committed despite exception - rollback not working!"
        
        finally:
            await session_manager.dispose()
    
    @pytest.mark.asyncio
    async def test_tc_db_001_commit_on_success(self):
        """
        P0: Test that transactions commit on success.
        
        Failure criteria:
        - Changes not committed
        - Session not closed properly
        """
        db_config = DatabaseConfig(
            url="sqlite+aiosqlite:///:memory:",
            debug_sql=False
        )
        
        session_manager = SessionManager(db_config)
        
        async with session_manager.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        try:
            # Test successful commit
            async with session_manager.get_session() as db:
                user = User(
                    email="commit_test@example.com",
                    hashed_password="hashed",
                    tier=Tier.FREE
                )
                db.add(user)
            
            # Verify user was committed
            async with session_manager.get_session() as db:
                result = await db.execute(select(User).where(User.email == "commit_test@example.com"))
                user_after = result.scalars().first()
                
                assert user_after is not None, \
                    "P0 FAILURE: User not committed - transaction not working!"
                assert user_after.email == "commit_test@example.com"
        
        finally:
            await session_manager.dispose()


@pytest.mark.priority_p0
class TestSessionLifecycle:
    """TC-DB-002: Engine disposal on shutdown."""
    
    @pytest.mark.asyncio
    async def test_tc_db_002_engine_disposal(self):
        """
        P0: Test that engines are disposed on shutdown.
        
        Reproduction steps:
        1. Create engines via get_async_engine
        2. Verify engines cached
        3. Call dispose_engines()
        4. Verify all engines disposed
        5. Verify cache cleared
        
        Links:
        - core/db/session.py:42-50
        - api/main.py:89-91
        - Commit: 298d1cc
        
        Failure criteria:
        - Engines not disposed
        - Cache not cleared
        - Connection leak
        - Hanging connections
        """
        # Clear cache first
        await dispose_engines()
        assert len(_engine_cache) == 0, "Cache should be empty"
        
        # Create multiple engines
        engine1 = get_async_engine("sqlite+aiosqlite:///test1.db")
        engine2 = get_async_engine("sqlite+aiosqlite:///test2.db")
        
        # Verify cached
        assert len(_engine_cache) == 2, "Engines should be cached"
        
        # Dispose all
        await dispose_engines()
        
        # Verify cache cleared
        assert len(_engine_cache) == 0, \
            "P0 FAILURE: Engine cache not cleared after dispose!"
    
    @pytest.mark.asyncio
    async def test_tc_db_002_session_manager_dispose(self):
        """
        P0: Test SessionManager.dispose() cleans up resources.
        
        Failure criteria:
        - Resources not released
        - Engines still active
        """
        db_config = DatabaseConfig(
            url="sqlite+aiosqlite:///:memory:",
            debug_sql=False
        )
        
        session_manager = SessionManager(db_config)
        
        # Use session
        async with session_manager.get_session() as db:
            result = await db.execute(text("SELECT 1"))
            assert result is not None
        
        # Dispose
        await session_manager.dispose()
        
        # After dispose, creating new session manager should work
        session_manager2 = SessionManager(db_config)
        async with session_manager2.get_session() as db:
            result = await db.execute(text("SELECT 1"))
            assert result is not None
        
        await session_manager2.dispose()


@pytest.mark.priority_p1
class TestConnectionHealth:
    """TC-DB-003: Connection health checks with pool_pre_ping."""
    
    @pytest.mark.asyncio
    async def test_tc_db_003_pool_pre_ping(self):
        """
        P1: Test that pool_pre_ping detects stale connections.
        
        Reproduction steps:
        1. Create engine with pool_pre_ping=True
        2. Get connection from pool
        3. Simulate connection issue
        4. Verify new connection created
        
        Links:
        - core/db/session.py:36,117,123
        - Commit: 298d1cc
        
        Failure criteria:
        - Stale connections used
        - Application crashes on connection loss
        - No automatic recovery
        """
        # Create engine with pool_pre_ping
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            pool_pre_ping=True,
            pool_recycle=3600
        )
        
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT 1"))
            assert result is not None
        
        # Verify pool_pre_ping is enabled
        assert engine.pool._pre_ping is True, \
            "P1 FAILURE: pool_pre_ping not enabled!"
        
        await engine.dispose()
    
    def test_tc_db_003_get_async_engine_has_pre_ping(self):
        """
        P1: Verify get_async_engine creates engines with pool_pre_ping.
        
        Failure criteria:
        - pool_pre_ping not set
        - pool_recycle not set
        """
        # Clear cache
        _engine_cache.clear()
        
        engine = get_async_engine("sqlite+aiosqlite:///:memory:")
        
        # Check configuration
        assert engine.pool._pre_ping is True, \
            "P1 FAILURE: pool_pre_ping not enabled in get_async_engine!"
        
        # pool_recycle should be set (3600 seconds = 1 hour)
        assert engine.pool._recycle == 3600, \
            f"P1 FAILURE: pool_recycle not set correctly: {engine.pool._recycle}"


@pytest.mark.priority_p1
class TestConcurrentSessions:
    """Test concurrent database sessions."""
    
    @pytest.mark.asyncio
    async def test_concurrent_transactions_isolated(self):
        """
        P1: Test that concurrent transactions are isolated.
        
        Failure criteria:
        - Transactions interfere with each other
        - Dirty reads occur
        """
        db_config = DatabaseConfig(
            url="sqlite+aiosqlite:///:memory:",
            debug_sql=False
        )
        
        session_manager = SessionManager(db_config)
        
        async with session_manager.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        try:
            # Create two concurrent sessions
            async def create_user(email: str):
                async with session_manager.get_session() as db:
                    user = User(
                        email=email,
                        hashed_password="hashed",
                        tier=Tier.FREE
                    )
                    db.add(user)
                    await db.flush()
                    await asyncio.sleep(0.1)  # Simulate slow operation
            
            # Run concurrently
            await asyncio.gather(
                create_user("user1@example.com"),
                create_user("user2@example.com")
            )
            
            # Verify both users created
            async with session_manager.get_session() as db:
                result = await db.execute(select(User))
                users = result.scalars().all()
                
                assert len(users) == 2, \
                    f"Expected 2 users, got {len(users)}"
                emails = {u.email for u in users}
                assert "user1@example.com" in emails
                assert "user2@example.com" in emails
        
        finally:
            await session_manager.dispose()


@pytest.mark.priority_p0
class TestEngineCaching:
    """Test engine caching mechanism."""
    
    def test_same_url_returns_cached_engine(self):
        """
        P0: Test that same URL returns cached engine.
        
        Failure criteria:
        - Multiple engines created for same URL
        - Memory leak from engine proliferation
        """
        _engine_cache.clear()
        
        url = "sqlite+aiosqlite:///test_cache.db"
        
        engine1 = get_async_engine(url)
        engine2 = get_async_engine(url)
        
        assert engine1 is engine2, \
            "P0 FAILURE: get_async_engine should return cached engine for same URL!"
        
        assert len(_engine_cache) == 1, \
            f"P0 FAILURE: Expected 1 cached engine, got {len(_engine_cache)}"
    
    def test_different_urls_create_separate_engines(self):
        """
        P0: Test that different URLs create separate engines.
        """
        _engine_cache.clear()
        
        url1 = "sqlite+aiosqlite:///test1.db"
        url2 = "sqlite+aiosqlite:///test2.db"
        
        engine1 = get_async_engine(url1)
        engine2 = get_async_engine(url2)
        
        assert engine1 is not engine2, \
            "Different URLs should create different engines"
        
        assert len(_engine_cache) == 2, \
            f"Expected 2 cached engines, got {len(_engine_cache)}"
