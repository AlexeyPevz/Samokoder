from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from samokoder.core.config import get_config
from typing import Generator, AsyncGenerator
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from contextlib import asynccontextmanager

from samokoder.core.db.setup import _async_to_sync_db_scheme


_engine_cache = {}

def get_async_engine(db_url: str = None):
    """Get or create an async database engine.
    
    Note: This function maintains a cache of engines per URL to avoid
    creating multiple engines for the same database. Engines are
    thread-safe and designed to be reused.
    
    Args:
        db_url: Database URL. If None, uses config.db.url
        
    Returns:
        AsyncEngine instance
    """
    if db_url is None:
        config = get_config()
        db_url = config.db.url
    
    if db_url not in _engine_cache:
        _engine_cache[db_url] = create_async_engine(
            db_url, 
            echo=False,
            pool_pre_ping=True,  # Enable connection health checks
            pool_recycle=3600,   # Recycle connections after 1 hour
        )
    return _engine_cache[db_url]


async def dispose_engines():
    """Dispose all cached database engines.
    
    Should be called on application shutdown to cleanly close
    all database connections.
    """
    for engine in _engine_cache.values():
        await engine.dispose()
    _engine_cache.clear()


Base = declarative_base()

def get_db() -> Generator:
    config = get_config()
    sync_engine = create_engine(_async_to_sync_db_scheme(config.db.url), echo=config.db.debug_sql)
    SyncSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)
    db = SyncSessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_async_db(db_url: str = None) -> AsyncGenerator[AsyncSession, None]:
    engine = get_async_engine(db_url)
    AsyncSessionLocal = sessionmaker(
        autocommit=False, 
        autoflush=False, 
        bind=engine, 
        class_=AsyncSession,
        expire_on_commit=False
    )
    db = AsyncSessionLocal()
    try:
        yield db
    finally:
        await db.close()


class _AsyncSessionContext:
    """Internal context manager for database sessions with automatic transaction handling."""
    
    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.session = None
    
    async def __aenter__(self) -> AsyncSession:
        """Create and return a new database session."""
        self.session = self.session_factory()
        return self.session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close session and handle transaction cleanup.
        
        - Commits transaction on success
        - Rolls back transaction on exception
        - Always closes the session
        """
        try:
            if exc_type is not None:
                await self.session.rollback()
            else:
                await self.session.commit()
        finally:
            await self.session.close()

class SessionManager:
    """Database session manager with proper resource cleanup."""
    
    def __init__(self, db_config):
        self.db_config = db_config
        self.sync_engine = create_engine(
            _async_to_sync_db_scheme(db_config.url), 
            echo=db_config.debug_sql,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        self.async_engine = create_async_engine(
            db_config.url, 
            echo=db_config.debug_sql,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        self.SyncSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.sync_engine)
        self.AsyncSessionLocal = sessionmaker(
            autocommit=False, 
            autoflush=False, 
            bind=self.async_engine, 
            class_=AsyncSession,
            expire_on_commit=False
        )
    
    async def start(self) -> AsyncSession:
        """Start a new async database session."""
        return self.AsyncSessionLocal()
    
    async def close(self, session: AsyncSession = None):
        """Close the database session."""
        if session:
            await session.close()
    
    def get_session(self):
        """Get a new async database session context manager.
        
        Returns an async context manager that yields an AsyncSession.
        Automatically handles commit on success and rollback on exception.
        
        Usage:
            async with session_manager.get_session() as db:
                # use db session
        """
        return _AsyncSessionContext(self.AsyncSessionLocal)
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = await self.start()
        return self.session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if exc_type is not None:
            await self.session.rollback()
        await self.close(self.session)
    
    async def dispose(self):
        """Dispose database engines and release all connections.
        
        Should be called when the SessionManager is no longer needed
        to ensure all database connections are properly closed.
        """
        await self.async_engine.dispose()
        self.sync_engine.dispose()
