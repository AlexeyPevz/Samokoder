"""
Тесты для AI API endpoints - простые тесты для увеличения покрытия
"""
import pytest
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, status
from fastapi.responses import StreamingResponse

# Импорт модулей для тестирования
from backend.api.ai import router, chat_with_ai, chat_with_ai_stream, get_ai_usage, get_ai_providers, validate_ai_keys
from backend.models.requests import ChatRequest
from backend.models.responses import AIResponse, AIUsageStatsResponse, AIUsageInfo


class TestAIApiEndpoints:
    """Тесты для AI API endpoints"""

    @pytest.fixture
    def mock_user(self):
        """Мок пользователя"""
        return {
            "id": "test-user-id",
            "email": "test@example.com",
            "role": "user"
        }

    @pytest.fixture
    def mock_chat_request(self):
        """Мок запроса чата"""
        return ChatRequest(
            message="Test message",
            context="test_context",
            model="deepseek/deepseek-v3",
            provider="openrouter"
        )

    @pytest.fixture
    def mock_ai_response(self):
        """Мок ответа AI"""
        return {
            "content": "Test AI response",
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30,
                "prompt_cost": 0.001,
                "completion_cost": 0.002,
                "total_cost": 0.003,
                "cost": 0.003
            },
            "response_time": 1.5
        }

    @pytest.fixture
    def mock_user_settings(self):
        """Мок настроек пользователя"""
        return {
            "user_id": "test-user-id",
            "default_model": "deepseek/deepseek-v3",
            "default_provider": "openrouter"
        }

    @pytest.mark.asyncio
    async def test_chat_with_ai_success(self, mock_user, mock_chat_request, mock_ai_response, mock_user_settings):
        """Тест успешного чата с AI"""
        with patch('backend.api.ai.get_ai_service') as mock_get_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_ai_service = AsyncMock()
            mock_ai_service.chat_completion.return_value = mock_ai_response
            mock_get_service.return_value = mock_ai_service
            
            mock_supabase.side_effect = [
                Mock(data=[mock_user_settings]),  # user_settings
                Mock(data=None)  # usage insert
            ]
            
            # Вызов функции
            result = await chat_with_ai(
                chat_request=mock_chat_request,
                current_user=mock_user,
                rate_limit={}
            )
            
            # Проверки
            assert isinstance(result, AIResponse)
            assert result.content == "Test AI response"
            assert result.model == "deepseek/deepseek-v3"
            assert result.provider == "openrouter"
            assert result.response_time == 1.5
            assert result.tokens_used == 30
            assert result.cost_usd == 0.003
            assert isinstance(result.usage, AIUsageInfo)

    @pytest.mark.asyncio
    async def test_chat_with_ai_no_user_settings(self, mock_user, mock_chat_request, mock_ai_response):
        """Тест чата с AI без настроек пользователя"""
        with patch('backend.api.ai.get_ai_service') as mock_get_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_ai_service = AsyncMock()
            mock_ai_service.chat_completion.return_value = mock_ai_response
            mock_get_service.return_value = mock_ai_service
            
            mock_supabase.side_effect = [
                Mock(data=[]),  # пустые user_settings
                Mock(data=None)  # usage insert
            ]
            
            # Вызов функции
            result = await chat_with_ai(
                chat_request=mock_chat_request,
                current_user=mock_user,
                rate_limit={}
            )
            
            # Проверки - должны использоваться значения по умолчанию
            assert result.model == "deepseek/deepseek-v3"
            assert result.provider == "openrouter"

    @pytest.mark.asyncio
    async def test_chat_with_ai_exception(self, mock_user, mock_chat_request):
        """Тест исключения в чате с AI"""
        with patch('backend.api.ai.get_ai_service') as mock_get_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков для исключения
            mock_get_service.side_effect = Exception("AI service error")
            mock_supabase.return_value = Mock(data=[{}])
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await chat_with_ai(
                    chat_request=mock_chat_request,
                    current_user=mock_user,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "AI chat failed"

    @pytest.mark.asyncio
    async def test_chat_with_ai_stream_success(self, mock_user, mock_chat_request, mock_user_settings):
        """Тест успешного стриминга чата с AI"""
        with patch('backend.api.ai.get_ai_service') as mock_get_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_ai_service = AsyncMock()
            mock_chunks = [
                {"content": "Hello"},
                {"content": " World"},
                {"content": "!"}
            ]
            
            async def mock_stream():
                for chunk in mock_chunks:
                    yield chunk
            
            mock_ai_service.chat_completion_stream.return_value = mock_stream()
            mock_get_service.return_value = mock_ai_service
            
            mock_supabase.return_value = Mock(data=[mock_user_settings])
            
            # Вызов функции
            result = await chat_with_ai_stream(
                chat_request=mock_chat_request,
                current_user=mock_user,
                rate_limit={}
            )
            
            # Проверки
            assert isinstance(result, StreamingResponse)
            assert result.media_type == "text/plain"

    @pytest.mark.asyncio
    async def test_chat_with_ai_stream_exception(self, mock_user, mock_chat_request):
        """Тест исключения в стриминге чата с AI"""
        with patch('backend.api.ai.get_ai_service') as mock_get_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков для исключения
            mock_get_service.side_effect = Exception("AI service error")
            mock_supabase.return_value = Mock(data=[{}])
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await chat_with_ai_stream(
                    chat_request=mock_chat_request,
                    current_user=mock_user,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "AI stream chat failed"

    @pytest.mark.asyncio
    async def test_get_ai_usage_success(self, mock_user):
        """Тест успешного получения статистики использования AI"""
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_usage_data = [
                {
                    "tokens_used": 100,
                    "cost": 0.01,
                    "provider": "openrouter"
                },
                {
                    "tokens_used": 200,
                    "cost": 0.02,
                    "provider": "openrouter"
                },
                {
                    "tokens_used": 50,
                    "cost": 0.005,
                    "provider": "anthropic"
                }
            ]
            
            mock_supabase.return_value = Mock(data=mock_usage_data)
            
            # Вызов функции
            result = await get_ai_usage(
                current_user=mock_user,
                days=30,
                rate_limit={}
            )
            
            # Проверки
            assert isinstance(result, AIUsageStatsResponse)
            assert result.total_tokens == 350
            assert result.total_cost == 0.035
            assert result.total_requests == 3
            assert result.success_rate == 100.0
            assert "openrouter" in result.providers
            assert "anthropic" in result.providers

    @pytest.mark.asyncio
    async def test_get_ai_usage_exception(self, mock_user):
        """Тест исключения при получении статистики использования AI"""
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков для исключения
            mock_supabase.side_effect = Exception("Database error")
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await get_ai_usage(
                    current_user=mock_user,
                    days=30,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "Failed to get AI usage"

    @pytest.mark.asyncio
    async def test_get_ai_providers_success(self, mock_user):
        """Тест успешного получения AI провайдеров"""
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_providers_data = [
                {
                    "id": "openrouter",
                    "name": "OpenRouter",
                    "display_name": "OpenRouter",
                    "website_url": "https://openrouter.ai",
                    "documentation_url": "https://openrouter.ai/docs",
                    "requires_api_key": True,
                    "pricing_info": {"per_token": 0.0001}
                },
                {
                    "id": "anthropic",
                    "name": "Anthropic",
                    "display_name": "Anthropic",
                    "website_url": "https://anthropic.com",
                    "documentation_url": "https://docs.anthropic.com",
                    "requires_api_key": True,
                    "pricing_info": {"per_token": 0.0002}
                }
            ]
            
            mock_supabase.return_value = Mock(data=mock_providers_data)
            
            # Вызов функции
            result = await get_ai_providers(
                current_user=mock_user,
                rate_limit={}
            )
            
            # Проверки
            assert "providers" in result
            assert len(result["providers"]) == 2
            assert result["providers"][0]["id"] == "openrouter"
            assert result["providers"][1]["id"] == "anthropic"

    @pytest.mark.asyncio
    async def test_get_ai_providers_exception(self, mock_user):
        """Тест исключения при получении AI провайдеров"""
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков для исключения
            mock_supabase.side_effect = Exception("Database error")
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await get_ai_providers(
                    current_user=mock_user,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "Failed to get AI providers"

    @pytest.mark.asyncio
    async def test_validate_ai_keys_success(self, mock_user):
        """Тест успешной валидации AI ключей"""
        keys_data = {
            "openrouter": "sk-or-1234567890",
            "anthropic": "sk-ant-1234567890"
        }
        
        # Вызов функции
        result = await validate_ai_keys(
            keys_data=keys_data,
            current_user=mock_user,
            rate_limit={}
        )
        
        # Проверки
        assert "validated_keys" in result
        assert "errors" in result
        assert result["total_valid"] == 2
        assert result["total_invalid"] == 0
        assert "openrouter" in result["validated_keys"]
        assert "anthropic" in result["validated_keys"]

    @pytest.mark.asyncio
    async def test_validate_ai_keys_invalid(self, mock_user):
        """Тест валидации невалидных AI ключей"""
        keys_data = {
            "openrouter": "short",
            "anthropic": "",
            "valid": "sk-valid-key-1234567890"
        }
        
        # Вызов функции
        result = await validate_ai_keys(
            keys_data=keys_data,
            current_user=mock_user,
            rate_limit={}
        )
        
        # Проверки
        assert result["total_valid"] == 1
        assert result["total_invalid"] == 2
        assert "openrouter" in result["errors"]
        assert "anthropic" in result["errors"]
        assert "valid" in result["validated_keys"]

    @pytest.mark.asyncio
    async def test_validate_ai_keys_exception(self, mock_user):
        """Тест исключения при валидации AI ключей"""
        # Проверка исключения с невалидными данными
        with pytest.raises(HTTPException) as exc_info:
            await validate_ai_keys(
                keys_data=None,  # None вместо dict
                current_user=mock_user,
                rate_limit={}
            )
        
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail == "Failed to validate AI keys"

    @pytest.mark.asyncio
    async def test_chat_request_model_validation(self):
        """Тест валидации модели ChatRequest"""
        # Валидный запрос
        valid_request = ChatRequest(
            message="Test message"
        )
        assert valid_request.message == "Test message"
        assert valid_request.context == "chat"  # значение по умолчанию
        assert valid_request.model is None
        assert valid_request.provider is None
        assert valid_request.max_tokens == 4096
        assert valid_request.temperature == 0.7

    @pytest.mark.asyncio
    async def test_ai_response_model_validation(self):
        """Тест валидации модели AIResponse"""
        usage_info = AIUsageInfo(
            prompt_tokens=10,
            completion_tokens=20,
            total_tokens=30,
            prompt_cost=0.001,
            completion_cost=0.002,
            total_cost=0.003
        )
        
        response = AIResponse(
            content="Test response",
            model="deepseek/deepseek-v3",
            provider="openrouter",
            response_time=1.5,
            tokens_used=30,
            cost_usd=0.003,
            usage=usage_info
        )
        
        assert response.content == "Test response"
        assert response.model == "deepseek/deepseek-v3"
        assert response.provider == "openrouter"
        assert response.response_time == 1.5
        assert response.tokens_used == 30
        assert response.cost_usd == 0.003
        assert isinstance(response.usage, AIUsageInfo)

    @pytest.mark.asyncio
    async def test_ai_usage_stats_response_model(self):
        """Тест валидации модели AIUsageStatsResponse"""
        provider_stats = {
            "openrouter": {"tokens": 300, "cost": 0.03, "requests": 2},
            "anthropic": {"tokens": 50, "cost": 0.005, "requests": 1}
        }
        
        response = AIUsageStatsResponse(
            total_requests=3,
            total_tokens=350,
            total_cost=0.035,
            success_rate=100.0,
            providers=provider_stats
        )
        
        assert response.total_tokens == 350
        assert response.total_cost == 0.035
        assert response.total_requests == 3
        assert response.success_rate == 100.0
        assert len(response.providers) == 2

    def test_router_initialization(self):
        """Тест инициализации роутера"""
        assert router is not None
        assert hasattr(router, 'routes')
        assert len(router.routes) > 0

    def test_ai_endpoints_import(self):
        """Тест импорта AI endpoints"""
        from backend.api.ai import router
        assert router is not None
        
        # Проверка наличия основных функций
        from backend.api.ai import (
            chat_with_ai,
            chat_with_ai_stream,
            get_ai_usage,
            get_ai_providers,
            validate_ai_keys
        )
        assert chat_with_ai is not None
        assert chat_with_ai_stream is not None
        assert get_ai_usage is not None
        assert get_ai_providers is not None
        assert validate_ai_keys is not None

    @pytest.mark.asyncio
    async def test_chat_with_ai_no_usage_data(self, mock_user, mock_chat_request):
        """Тест чата с AI без данных использования"""
        with patch('backend.api.ai.get_ai_service') as mock_get_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков без usage данных
            mock_ai_response = {
                "content": "Test response",
                "response_time": 1.5
                # Нет usage данных
            }
            
            mock_ai_service = AsyncMock()
            mock_ai_service.chat_completion.return_value = mock_ai_response
            mock_get_service.return_value = mock_ai_service
            
            mock_supabase.return_value = Mock(data=[{}])
            
            # Вызов функции
            result = await chat_with_ai(
                chat_request=mock_chat_request,
                current_user=mock_user,
                rate_limit={}
            )
            
            # Проверки
            assert result.content == "Test response"
            assert result.tokens_used is None
            assert result.cost_usd is None
            assert result.usage is not None  # AIUsageInfo всегда создается
            assert result.usage.total_tokens is None

    @pytest.mark.asyncio
    async def test_get_ai_usage_empty_data(self, mock_user):
        """Тест получения статистики AI с пустыми данными"""
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков с пустыми данными
            mock_supabase.return_value = Mock(data=[])
            
            # Вызов функции
            result = await get_ai_usage(
                current_user=mock_user,
                days=7,
                rate_limit={}
            )
            
            # Проверки
            assert result.total_tokens == 0
            assert result.total_cost == 0.0
            assert result.total_requests == 0
            assert result.success_rate == 100.0
            assert result.providers == {}

    @pytest.mark.asyncio
    async def test_get_ai_providers_empty_data(self, mock_user):
        """Тест получения AI провайдеров с пустыми данными"""
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков с пустыми данными
            mock_supabase.return_value = Mock(data=[])
            
            # Вызов функции
            result = await get_ai_providers(
                current_user=mock_user,
                rate_limit={}
            )
            
            # Проверки
            assert "providers" in result
            assert result["providers"] == []

    def test_ai_usage_info_model(self):
        """Тест модели AIUsageInfo"""
        usage_info = AIUsageInfo(
            prompt_tokens=10,
            completion_tokens=20,
            total_tokens=30,
            prompt_cost=0.001,
            completion_cost=0.002,
            total_cost=0.003
        )
        
        assert usage_info.prompt_tokens == 10
        assert usage_info.completion_tokens == 20
        assert usage_info.total_tokens == 30
        assert usage_info.prompt_cost == 0.001
        assert usage_info.completion_cost == 0.002
        assert usage_info.total_cost == 0.003

    @pytest.mark.asyncio
    async def test_validate_ai_keys_edge_cases(self, mock_user):
        """Тест граничных случаев валидации AI ключей"""
        # Тест с минимально валидным ключом
        keys_data = {
            "test": "1234567890"  # 10 символов - минимальная длина
        }
        
        result = await validate_ai_keys(
            keys_data=keys_data,
            current_user=mock_user,
            rate_limit={}
        )
        
        assert result["total_valid"] == 1
        assert result["total_invalid"] == 0
        
        # Тест с ключом длиной 9 символов
        keys_data = {
            "test": "123456789"  # 9 символов - слишком короткий
        }
        
        result = await validate_ai_keys(
            keys_data=keys_data,
            current_user=mock_user,
            rate_limit={}
        )
        
        assert result["total_valid"] == 0
        assert result["total_invalid"] == 1