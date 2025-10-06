"""
Общие фикстуры для контрактных тестов.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from samokoder.core.db.models.base import Base
from samokoder.core.db.session import get_db


@pytest.fixture(scope="function")
def db():
    """
    Создать тестовую базу данных в памяти для каждого теста.
    
    Используется SQLite in-memory для изоляции тестов.
    """
    # Создать in-memory SQLite БД
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    # Создать таблицы
    Base.metadata.create_all(bind=engine)
    
    # Создать сессию
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def override_get_db(db):
    """
    Override зависимости get_db для использования тестовой БД.
    """
    from samokoder.api.main import app
    
    def _override_get_db():
        try:
            yield db
        finally:
            pass
    
    app.dependency_overrides[get_db] = _override_get_db
    
    yield
    
    # Cleanup
    app.dependency_overrides.clear()
