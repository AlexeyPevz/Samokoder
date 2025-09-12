"""
Тесты для API Keys endpoints - простые тесты для увеличения покрытия
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, status
from datetime import datetime

# Импорт модулей для тестирования
from backend.api.api_keys import router
from backend.models.requests import APIKeyCreateRequest
from backend.models.responses import APIKeyResponse, APIKeyListResponse
from backend.models.requests import AIProvider


class TestAPIKeysEndpoints:
    """Тесты для API Keys endpoints"""

    @pytest.fixture
    def mock_user(self):
        """Мок пользователя"""
        return {
            "id": "test-user-id",
            "email": "test@example.com",
            "role": "user"
        }

    @pytest.fixture
    def mock_api_key_request(self):
        """Мок запроса создания API ключа"""
        return APIKeyCreateRequest(
            provider=AIProvider.OPENROUTER,
            key_name="Test API Key",
            api_key="sk-or-1234567890abcdef"
        )

    def test_router_initialization(self):
        """Тест инициализации роутера"""
        assert router is not None
        assert hasattr(router, 'routes')
        assert len(router.routes) > 0

    def test_api_keys_endpoints_import(self):
        """Тест импорта API Keys endpoints"""
        from backend.api.api_keys import router
        assert router is not None

    @pytest.mark.asyncio
    async def test_api_key_create_request_validation(self):
        """Тест валидации модели APIKeyCreateRequest"""
        # Валидный запрос
        valid_request = APIKeyCreateRequest(
            provider=AIProvider.OPENROUTER,
            key_name="Test Key",
            api_key="sk-or-1234567890abcdef"
        )
        
        assert valid_request.provider == AIProvider.OPENROUTER
        assert valid_request.key_name == "Test Key"
        assert valid_request.api_key == "sk-or-1234567890abcdef"

    @pytest.mark.asyncio
    async def test_api_key_create_request_anthropic(self):
        """Тест валидации модели APIKeyCreateRequest для Anthropic"""
        # Валидный запрос для Anthropic
        anthropic_request = APIKeyCreateRequest(
            provider=AIProvider.ANTHROPIC,
            key_name="Anthropic Key",
            api_key="sk-ant-1234567890abcdef"
        )
        
        assert anthropic_request.provider == AIProvider.ANTHROPIC
        assert anthropic_request.key_name == "Anthropic Key"
        assert anthropic_request.api_key == "sk-ant-1234567890abcdef"

    @pytest.mark.asyncio
    async def test_api_key_response_model_validation(self):
        """Тест валидации модели APIKeyResponse"""
        response = APIKeyResponse(
            id="test-key-id",
            provider="openrouter",
            key_name="Test Key",
            key_last_4="def",
            is_active=True,
            created_at="2024-01-01T00:00:00"
        )
        
        assert response.id == "test-key-id"
        assert response.provider == "openrouter"
        assert response.key_name == "Test Key"
        assert response.key_last_4 == "def"
        assert response.is_active is True
        assert response.created_at == "2024-01-01T00:00:00"

    @pytest.mark.asyncio
    async def test_api_key_list_response_model_validation(self):
        """Тест валидации модели APIKeyListResponse"""
        keys = [
            APIKeyResponse(
                id="key-1",
                provider="openrouter",
                key_name="Key 1",
                key_last_4="abcd",
                is_active=True,
                created_at="2024-01-01T00:00:00"
            ),
            APIKeyResponse(
                id="key-2",
                provider="anthropic",
                key_name="Key 2",
                key_last_4="efgh",
                is_active=False,
                created_at="2024-01-01T00:00:00"
            )
        ]
        
        response = APIKeyListResponse(keys=keys, total_count=2)
        
        assert response.total_count == 2
        assert len(response.keys) == 2
        assert response.keys[0].id == "key-1"
        assert response.keys[1].id == "key-2"

    @pytest.mark.asyncio
    async def test_api_key_response_inactive(self):
        """Тест модели APIKeyResponse с неактивным ключом"""
        response = APIKeyResponse(
            id="inactive-key-id",
            provider="openrouter",
            key_name="Inactive Key",
            key_last_4="xyz",
            is_active=False,
            created_at="2024-01-01T00:00:00"
        )
        
        assert response.id == "inactive-key-id"
        assert response.provider == "openrouter"
        assert response.key_name == "Inactive Key"
        assert response.key_last_4 == "xyz"
        assert response.is_active is False

    @pytest.mark.asyncio
    async def test_api_key_list_response_empty(self):
        """Тест модели APIKeyListResponse с пустым списком"""
        response = APIKeyListResponse(keys=[], total_count=0)
        
        assert response.total_count == 0
        assert len(response.keys) == 0

    @pytest.mark.asyncio
    async def test_api_key_create_request_validation_min_length(self):
        """Тест валидации минимальной длины API ключа"""
        # Ключ с минимальной длиной (10 символов) - правильный формат для OpenRouter
        request = APIKeyCreateRequest(
            provider=AIProvider.OPENROUTER,
            key_name="Min Length Key",
            api_key="sk-or-12345"
        )
        
        assert len(request.api_key) == 11
        assert request.api_key == "sk-or-12345"

    @pytest.mark.asyncio
    async def test_api_key_create_request_validation_max_length(self):
        """Тест валидации максимальной длины API ключа"""
        # Ключ с максимальной длиной (200 символов) - правильный формат для OpenRouter
        long_key = "sk-or-" + "a" * 194  # 200 символов
        request = APIKeyCreateRequest(
            provider=AIProvider.OPENROUTER,
            key_name="Max Length Key",
            api_key=long_key
        )
        
        assert len(request.api_key) == 200
        assert request.api_key == long_key

    @pytest.mark.asyncio
    async def test_api_key_create_request_validation_key_name_min_length(self):
        """Тест валидации минимальной длины названия ключа"""
        # Название с минимальной длиной (1 символ)
        request = APIKeyCreateRequest(
            provider=AIProvider.OPENROUTER,
            key_name="A",
            api_key="sk-or-1234567890"
        )
        
        assert len(request.key_name) == 1
        assert request.key_name == "A"

    @pytest.mark.asyncio
    async def test_api_key_create_request_validation_key_name_max_length(self):
        """Тест валидации максимальной длины названия ключа"""
        # Название с максимальной длиной (50 символов)
        long_name = "A" * 50
        request = APIKeyCreateRequest(
            provider=AIProvider.OPENROUTER,
            key_name=long_name,
            api_key="sk-or-1234567890"
        )
        
        assert len(request.key_name) == 50
        assert request.key_name == long_name

    @pytest.mark.asyncio
    async def test_api_key_response_different_providers(self):
        """Тест модели APIKeyResponse для разных провайдеров"""
        providers = ["openrouter", "anthropic", "openai", "claude"]
        
        for i, provider in enumerate(providers):
            response = APIKeyResponse(
                id=f"key-{i}",
                provider=provider,
                key_name=f"Key {i}",
                key_last_4=f"{i:04}",
                is_active=True,
                created_at="2024-01-01T00:00:00"
            )
            
            assert response.id == f"key-{i}"
            assert response.provider == provider
            assert response.key_name == f"Key {i}"
            assert response.key_last_4 == f"{i:04}"

    @pytest.mark.asyncio
    async def test_api_key_list_response_large_list(self):
        """Тест модели APIKeyListResponse с большим списком"""
        keys = []
        for i in range(10):
            keys.append(APIKeyResponse(
                id=f"key-{i}",
                provider="openrouter",
                key_name=f"Key {i}",
                key_last_4=f"{i:04}",
                is_active=i % 2 == 0,  # Четные активны, нечетные неактивны
                created_at="2024-01-01T00:00:00"
            ))
        
        response = APIKeyListResponse(keys=keys, total_count=10)
        
        assert response.total_count == 10
        assert len(response.keys) == 10
        
        # Проверяем, что активные и неактивные ключи правильно распределены
        active_count = sum(1 for key in response.keys if key.is_active)
        inactive_count = sum(1 for key in response.keys if not key.is_active)
        
        assert active_count == 5  # Четные индексы (0, 2, 4, 6, 8)
        assert inactive_count == 5  # Нечетные индексы (1, 3, 5, 7, 9)

    @pytest.mark.asyncio
    async def test_api_key_response_edge_cases(self):
        """Тест граничных случаев для APIKeyResponse"""
        # Тест с пустым названием ключа (после trim)
        response = APIKeyResponse(
            id="edge-case-key",
            provider="openrouter",
            key_name="  ",
            key_last_4="edge",
            is_active=True,
            created_at="2024-01-01T00:00:00"
        )
        
        assert response.key_name == "  "  # Пробелы сохраняются
        
        # Тест с очень длинным ID
        long_id = "a" * 100
        response = APIKeyResponse(
            id=long_id,
            provider="openrouter",
            key_name="Long ID Key",
            key_last_4="long",
            is_active=False,
            created_at="2024-01-01T00:00:00"
        )
        
        assert len(response.id) == 100
        assert response.id == long_id

    @pytest.mark.asyncio
    async def test_api_key_create_request_anthropic_validation(self):
        """Тест валидации Anthropic ключей"""
        # Валидный Anthropic ключ
        anthropic_request = APIKeyCreateRequest(
            provider=AIProvider.ANTHROPIC,
            key_name="Anthropic Test",
            api_key="sk-ant-api03-1234567890abcdef"
        )
        
        assert anthropic_request.provider == AIProvider.ANTHROPIC
        assert anthropic_request.api_key.startswith("sk-ant-")

    @pytest.mark.asyncio
    async def test_api_key_create_request_openrouter_validation(self):
        """Тест валидации OpenRouter ключей"""
        # Валидный OpenRouter ключ
        openrouter_request = APIKeyCreateRequest(
            provider=AIProvider.OPENROUTER,
            key_name="OpenRouter Test",
            api_key="sk-or-v1-1234567890abcdef"
        )
        
        assert openrouter_request.provider == AIProvider.OPENROUTER
        assert openrouter_request.api_key.startswith("sk-or-")

    @pytest.mark.asyncio
    async def test_api_key_response_created_at_formats(self):
        """Тест различных форматов created_at"""
        formats = [
            "2024-01-01T00:00:00",
            "2024-12-31T23:59:59",
            "2023-06-15T12:30:45",
            "2025-03-20T08:15:30"
        ]
        
        for i, date_format in enumerate(formats):
            response = APIKeyResponse(
                id=f"date-key-{i}",
                provider="openrouter",
                key_name=f"Date Key {i}",
                key_last_4=f"{i:04}",
                is_active=True,
                created_at=date_format
            )
            
            assert response.created_at == date_format

    def test_ai_provider_enum_values(self):
        """Тест значений AIProvider enum"""
        assert AIProvider.OPENROUTER.value == "openrouter"
        assert AIProvider.ANTHROPIC.value == "anthropic"
        assert AIProvider.OPENAI.value == "openai"
        assert AIProvider.GROQ.value == "groq"

    def test_api_key_create_request_provider_enum(self):
        """Тест использования AIProvider enum в запросе"""
        # Тестируем каждый провайдер с правильным форматом ключа
        test_cases = [
            (AIProvider.OPENROUTER, "sk-or-1234567890"),
            (AIProvider.ANTHROPIC, "sk-ant-1234567890"),
            (AIProvider.OPENAI, "sk-1234567890abcdef"),
            (AIProvider.GROQ, "gsk_1234567890abcdef")
        ]
        
        for provider, api_key in test_cases:
            request = APIKeyCreateRequest(
                provider=provider,
                key_name=f"{provider.value} Key",
                api_key=api_key
            )
            
            assert request.provider == provider
            assert request.provider.value == provider.value
            assert request.api_key == api_key