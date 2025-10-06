"""Fixtures for regression tests."""
import pytest
import asyncio
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession as AsyncSessionType
from passlib.context import CryptContext

from samokoder.api.main import app
from samokoder.core.db.models.base import Base
from samokoder.core.db.models.user import User, Tier
from samokoder.core.db.models.login_attempts import LoginAttempt
from samokoder.core.db.models.revoked_tokens import RevokedToken
from samokoder.core.db.session import get_async_db
from samokoder.core.config import get_config


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
def test_db_engine():
    """Create a test database engine."""
    # Use in-memory SQLite for tests
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="function")
def test_db_session(test_db_engine):
    """Create a test database session."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    session = TestingSessionLocal()
    yield session
    session.close()


@pytest.fixture(scope="function")
def client(test_db_session):
    """Create a test client with database override."""
    
    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass
    
    async def override_get_async_db():
        # For sync tests, we use sync session
        yield test_db_session
    
    app.dependency_overrides[get_async_db] = override_get_async_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(test_db_session) -> User:
    """Create a test user in the database."""
    user = User(
        email="testuser@example.com",
        hashed_password=pwd_context.hash("TestPassword123!"),
        tier=Tier.FREE
    )
    test_db_session.add(user)
    test_db_session.commit()
    test_db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(client: TestClient, test_user: User) -> dict:
    """Get authentication headers for a test user."""
    response = client.post("/v1/auth/login", data={
        "username": test_user.email,
        "password": "TestPassword123!"
    })
    
    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}
    
    # Fallback if login via endpoint doesn't work
    from samokoder.core.config import get_config
    from jose import jwt
    from datetime import datetime, timedelta
    
    config = get_config()
    token = jwt.encode(
        {
            "sub": test_user.email,
            "exp": datetime.utcnow() + timedelta(minutes=15),
            "type": "access",
            "jti": "test-jti-123"
        },
        config.secret_key,
        algorithm="HS256"
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def weak_passwords():
    """List of weak passwords that should be rejected."""
    return [
        "short",  # Too short (< 8 chars)
        "nocapital123!",  # No uppercase
        "NOLOWERCASE123!",  # No lowercase  
        "NoNumbers!",  # No numbers
        "NoSpecialChar123",  # No special characters
        "Password123!",  # Common password
        "aaaaaa123A!",  # Repeated characters
    ]


@pytest.fixture
def strong_password():
    """A strong password that should be accepted."""
    return "StrongP@ss123"


@pytest.fixture
def cleanup_login_attempts(test_db_session):
    """Clean up login attempts before and after tests."""
    test_db_session.query(LoginAttempt).delete()
    test_db_session.commit()
    yield
    test_db_session.query(LoginAttempt).delete()
    test_db_session.commit()


@pytest.fixture
def cleanup_revoked_tokens(test_db_session):
    """Clean up revoked tokens before and after tests."""
    test_db_session.query(RevokedToken).delete()
    test_db_session.commit()
    yield
    test_db_session.query(RevokedToken).delete()
    test_db_session.commit()
