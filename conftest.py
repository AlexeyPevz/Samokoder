"""
Исправленные фикстуры для тестов
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from test_app import test_app

@pytest.fixture(scope="session")
def event_loop():
    """Создание event loop для тестов"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def client():
    """Тестовый клиент без проблемных middleware"""
    return TestClient(test_app)

@pytest.fixture
def mock_connection_manager():
    """Мок для connection manager"""
    with patch('backend.services.connection_manager.connection_manager') as mock:
        # Настраиваем мок для connection manager
        mock.get_pool.return_value = MagicMock()
        mock._initialized = True
        mock._pools = {
            'supabase': MagicMock(),
            'redis': MagicMock(),
            'http': MagicMock(),
            'database': MagicMock()
        }
        yield mock

@pytest.fixture
def mock_supabase_operation():
    """Мок для Supabase операций"""
    with patch('backend.api.api_keys.execute_supabase_operation') as mock:
        yield mock

@pytest.fixture
def mock_encryption_service():
    """Мок для encryption service"""
    with patch('backend.api.api_keys.get_encryption_service') as mock:
        mock_service = MagicMock()
        mock_service.encrypt_api_key.return_value = "encrypted_key"
        mock_service.get_key_last_4.return_value = "1234"
        mock.return_value = mock_service
        yield mock

@pytest.fixture
def mock_redis_client():
    """Мок для Redis клиента"""
    with patch('backend.api.mfa.redis_client') as mock:
        mock.setex.return_value = True
        mock.get.return_value = b"test_secret"
        mock.delete.return_value = 1
        yield mock

@pytest.fixture
def mock_current_user():
    """Мок для текущего пользователя"""
    with patch('backend.auth.dependencies.get_current_user') as mock:
        mock.return_value = {"id": "test_user_123", "email": "test@example.com"}
        yield mock

@pytest.fixture
def mock_jwt_validation():
    """Мок для JWT валидации"""
    with patch('backend.auth.dependencies.validate_jwt_token') as mock:
        mock.return_value = True
        yield mock