"""
Конфигурация pytest для проекта Самокодер
"""

import pytest
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Добавляем корневую директорию в Python path
root_dir = Path(__file__).parent
sys.path.insert(0, str(root_dir))

# Настройка переменных окружения для тестов
os.environ["ENVIRONMENT"] = "test"
os.environ["DEBUG"] = "true"
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["SUPABASE_URL"] = "https://test.supabase.co"
os.environ["SUPABASE_ANON_KEY"] = "test-anon-key"
os.environ["API_ENCRYPTION_KEY"] = "test-encryption-key-32-chars-long"
os.environ["API_ENCRYPTION_SALT"] = "test-salt-16"

@pytest.fixture(scope="session")
def event_loop():
    """Создает event loop для всех тестов"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def mock_supabase():
    """Фикстура для мока Supabase"""
    mock_supabase = MagicMock()
    mock_supabase.auth.sign_in_with_password = AsyncMock()
    mock_supabase.auth.sign_out = AsyncMock()
    mock_supabase.auth.get_user = AsyncMock()
    mock_supabase.table.return_value.select.return_value.eq.return_value.execute = AsyncMock()
    return mock_supabase

@pytest.fixture
def mock_redis():
    """Фикстура для мока Redis"""
    mock_redis = AsyncMock()
    mock_redis.pipeline.return_value = AsyncMock()
    mock_redis.get = AsyncMock()
    mock_redis.set = AsyncMock()
    mock_redis.delete = AsyncMock()
    return mock_redis

@pytest.fixture
def sample_user():
    """Фикстура для тестового пользователя"""
    return {
        "id": "test-user-123",
        "email": "test@example.com",
        "full_name": "Test User",
        "subscription_tier": "free",
        "subscription_status": "active",
        "api_credits_balance": 10.0,
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z"
    }

@pytest.fixture
def sample_project():
    """Фикстура для тестового проекта"""
    return {
        "id": "test-project-123",
        "user_id": "test-user-123",
        "name": "Test Project",
        "description": "This is a test project",
        "status": "draft",
        "tech_stack": {"frontend": "React", "backend": "FastAPI"},
        "ai_config": {"provider": "openai", "model": "gpt-4o-mini"},
        "file_count": 0,
        "total_size_bytes": 0,
        "generation_time_seconds": 0,
        "generation_progress": 0,
        "current_agent": None,
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
        "archived_at": None
    }

@pytest.fixture
def sample_api_key():
    """Фикстура для тестового API ключа"""
    return {
        "id": "test-key-123",
        "user_id": "test-user-123",
        "provider": "openai",
        "key_name": "Test OpenAI Key",
        "api_key_encrypted": "encrypted-key-data",
        "api_key_last_4": "cdef",
        "is_active": True,
        "last_used_at": None,
        "created_at": "2025-01-01T00:00:00Z"
    }

@pytest.fixture
def sample_chat_messages():
    """Фикстура для тестовых сообщений чата"""
    return [
        {"role": "system", "content": "You are a helpful AI assistant."},
        {"role": "user", "content": "Hello, how are you?"},
        {"role": "assistant", "content": "Hello! I'm doing well, thank you for asking."}
    ]

@pytest.fixture
def sample_ai_response():
    """Фикстура для тестового AI ответа"""
    return {
        "content": "This is a test AI response.",
        "provider": "openai",
        "model": "gpt-4o-mini",
        "tokens_used": 25,
        "cost_usd": 0.001,
        "response_time": 1.5,
        "success": True,
        "error": None
    }

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Автоматическая настройка тестового окружения"""
    # Создаем тестовые директории
    test_dirs = ["exports", "workspaces", "logs", "backups"]
    for dir_name in test_dirs:
        Path(dir_name).mkdir(exist_ok=True)
    
    yield
    
    # Очистка после тестов
    import shutil
    for dir_name in test_dirs:
        if Path(dir_name).exists():
            shutil.rmtree(dir_name, ignore_errors=True)

@pytest.fixture
def mock_openai_client():
    """Фикстура для мока OpenAI клиента"""
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Test response from OpenAI"
    mock_response.usage.total_tokens = 25
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
    return mock_client

@pytest.fixture
def mock_anthropic_client():
    """Фикстура для мока Anthropic клиента"""
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = [MagicMock()]
    mock_response.content[0].text = "Test response from Anthropic"
    mock_response.usage.input_tokens = 10
    mock_response.usage.output_tokens = 15
    mock_client.messages.create = AsyncMock(return_value=mock_response)
    return mock_client

@pytest.fixture
def mock_groq_response():
    """Фикстура для мока Groq ответа"""
    return {
        "choices": [{"message": {"content": "Test response from Groq"}}],
        "usage": {"total_tokens": 20}
    }

# Маркеры для категоризации тестов
def pytest_configure(config):
    """Конфигурация pytest маркеров"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )

# Параметризация для тестирования разных провайдеров
@pytest.fixture(params=["openai", "anthropic", "openrouter", "groq"])
def ai_provider(request):
    """Фикстура для тестирования разных AI провайдеров"""
    return request.param

# Параметризация для тестирования разных размеров данных
@pytest.fixture(params=[1, 10, 100, 1000])
def data_size(request):
    """Фикстура для тестирования разных размеров данных"""
    return request.param