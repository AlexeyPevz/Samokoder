from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from samokoder.core.config import get_config
from typing import Generator, AsyncGenerator
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from samokoder.core.db.setup import _async_to_sync_db_scheme


async_engine = None

def get_async_engine(db_url: str = None):
    global async_engine
    if async_engine is None:
        if db_url is None:
            config = get_config()
            db_url = config.db.url
        async_engine = create_async_engine(db_url, echo=False)
    return async_engine


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

class SessionManager:
    """Database session manager."""
    
    def __init__(self, db_config):
        self.db_config = db_config
        self.sync_engine = create_engine(_async_to_sync_db_scheme(db_config.url), echo=db_config.debug_sql)
        self.async_engine = create_async_engine(db_config.url, echo=db_config.debug_sql)
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
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = await self.start()
        return self.session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close(self.session)
        if exc_type is not None:
            # Handle exceptions if needed
            pass
