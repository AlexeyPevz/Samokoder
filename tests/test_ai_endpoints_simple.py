"""
Простые тесты для AI endpoints
Тестируют все AI endpoints без FastAPI TestClient
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import HTTPException, status

class TestAIEndpointsSimple:
    """Простые тесты для AI endpoints"""
    
    def test_ai_endpoints_exist(self):
        """Проверяем, что все AI endpoints существуют"""
        from backend.api.ai import router
        
        # Проверяем, что router существует
        assert router is not None
        
        # Проверяем, что у router есть routes
        assert hasattr(router, 'routes')
        assert len(router.routes) > 0
    
    def test_chat_with_ai_function_exists(self):
        """Проверяем, что функция chat_with_ai существует"""
        from backend.api.ai import chat_with_ai
        
        # Проверяем, что функция существует и является async
        assert callable(chat_with_ai)
        import asyncio
        assert asyncio.iscoroutinefunction(chat_with_ai)
    
    def test_chat_with_ai_stream_function_exists(self):
        """Проверяем, что функция chat_with_ai_stream существует"""
        from backend.api.ai import chat_with_ai_stream
        
        # Проверяем, что функция существует и является async
        assert callable(chat_with_ai_stream)
        import asyncio
        assert asyncio.iscoroutinefunction(chat_with_ai_stream)
    
    def test_get_ai_usage_function_exists(self):
        """Проверяем, что функция get_ai_usage существует"""
        from backend.api.ai import get_ai_usage
        
        # Проверяем, что функция существует и является async
        assert callable(get_ai_usage)
        import asyncio
        assert asyncio.iscoroutinefunction(get_ai_usage)
    
    def test_get_ai_providers_function_exists(self):
        """Проверяем, что функция get_ai_providers существует"""
        from backend.api.ai import get_ai_providers
        
        # Проверяем, что функция существует и является async
        assert callable(get_ai_providers)
        import asyncio
        assert asyncio.iscoroutinefunction(get_ai_providers)
    
    def test_validate_ai_keys_function_exists(self):
        """Проверяем, что функция validate_ai_keys существует"""
        from backend.api.ai import validate_ai_keys
        
        # Проверяем, что функция существует и является async
        assert callable(validate_ai_keys)
        import asyncio
        assert asyncio.iscoroutinefunction(validate_ai_keys)
    
    @pytest.mark.asyncio
    async def test_chat_with_ai_success(self):
        """Тест успешного чата с AI"""
        from backend.api.ai import chat_with_ai
        
        # Создаем mock chat request
        mock_chat_request = MagicMock()
        mock_chat_request.message = "Hello, AI!"
        mock_chat_request.model = "deepseek/deepseek-v3"
        mock_chat_request.provider = "openrouter"
        mock_chat_request.context = {}
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.get_ai_service') as mock_get_ai_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настраиваем AI service mock
            mock_ai_service = MagicMock()
            mock_ai_service.chat_completion = AsyncMock(return_value={
                "response": "Hello! How can I help you?",
                "usage": {"tokens": 10, "cost": 0.001}
            })
            mock_get_ai_service.return_value = mock_ai_service
            
            # Настраиваем Supabase mock
            mock_supabase_response = MagicMock()
            mock_supabase_response.data = [{"default_model": "deepseek/deepseek-v3"}]
            mock_supabase.return_value = mock_supabase_response
            
            # Тестируем функцию
            result = await chat_with_ai(
                chat_request=mock_chat_request,
                current_user={"id": "user123"},
                rate_limit={}
            )
            
            # Проверяем результат
            assert result.response == "Hello! How can I help you?"
            assert result.usage.tokens == 10
            assert result.usage.cost == 0.001
            assert result.status == "success"
    
    @pytest.mark.asyncio
    async def test_chat_with_ai_no_user_settings(self):
        """Тест чата с AI без настроек пользователя"""
        from backend.api.ai import chat_with_ai
        
        # Создаем mock chat request
        mock_chat_request = MagicMock()
        mock_chat_request.message = "Hello, AI!"
        mock_chat_request.model = None
        mock_chat_request.provider = None
        mock_chat_request.context = {}
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.get_ai_service') as mock_get_ai_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настраиваем AI service mock
            mock_ai_service = MagicMock()
            mock_ai_service.chat_completion = AsyncMock(return_value={
                "response": "Hello! How can I help you?",
                "usage": {"tokens": 10, "cost": 0.001}
            })
            mock_get_ai_service.return_value = mock_ai_service
            
            # Настраиваем Supabase mock (пустые настройки)
            mock_supabase_response = MagicMock()
            mock_supabase_response.data = []
            mock_supabase.return_value = mock_supabase_response
            
            # Тестируем функцию
            result = await chat_with_ai(
                chat_request=mock_chat_request,
                current_user={"id": "user123"},
                rate_limit={}
            )
            
            # Проверяем результат
            assert result.response == "Hello! How can I help you?"
            assert result.status == "success"
    
    @pytest.mark.asyncio
    async def test_chat_with_ai_service_error(self):
        """Тест чата с AI с ошибкой сервиса"""
        from backend.api.ai import chat_with_ai
        
        # Создаем mock chat request
        mock_chat_request = MagicMock()
        mock_chat_request.message = "Hello, AI!"
        mock_chat_request.model = "deepseek/deepseek-v3"
        mock_chat_request.provider = "openrouter"
        mock_chat_request.context = {}
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.get_ai_service') as mock_get_ai_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настраиваем AI service mock с ошибкой
            mock_ai_service = MagicMock()
            mock_ai_service.chat_completion = AsyncMock(side_effect=Exception("AI service error"))
            mock_get_ai_service.return_value = mock_ai_service
            
            # Настраиваем Supabase mock
            mock_supabase_response = MagicMock()
            mock_supabase_response.data = []
            mock_supabase.return_value = mock_supabase_response
            
            # Тестируем функцию
            with pytest.raises(HTTPException) as exc_info:
                await chat_with_ai(
                    chat_request=mock_chat_request,
                    current_user={"id": "user123"},
                    rate_limit={}
                )
            
            # Проверяем, что возвращается правильная ошибка
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "AI service error" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_chat_with_ai_stream_success(self):
        """Тест успешного стримингового чата с AI"""
        from backend.api.ai import chat_with_ai_stream
        
        # Создаем mock chat request
        mock_chat_request = MagicMock()
        mock_chat_request.message = "Hello, AI!"
        mock_chat_request.model = "deepseek/deepseek-v3"
        mock_chat_request.provider = "openrouter"
        mock_chat_request.context = {}
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.get_ai_service') as mock_get_ai_service, \
             patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            
            # Настраиваем AI service mock для стриминга
            mock_ai_service = MagicMock()
            mock_ai_service.chat_completion = AsyncMock(return_value={
                "response": "Hello! How can I help you?",
                "usage": {"tokens": 10, "cost": 0.001}
            })
            mock_get_ai_service.return_value = mock_ai_service
            
            # Настраиваем Supabase mock
            mock_supabase_response = MagicMock()
            mock_supabase_response.data = []
            mock_supabase.return_value = mock_supabase_response
            
            # Тестируем функцию
            result = await chat_with_ai_stream(
                chat_request=mock_chat_request,
                current_user={"id": "user123"},
                rate_limit={}
            )
            
            # Проверяем, что возвращается StreamingResponse
            from fastapi.responses import StreamingResponse
            assert isinstance(result, StreamingResponse)
    
    @pytest.mark.asyncio
    async def test_get_ai_usage_success(self):
        """Тест успешного получения статистики использования AI"""
        from backend.api.ai import get_ai_usage
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            # Настраиваем Supabase mock
            mock_supabase_response = MagicMock()
            mock_supabase_response.data = [
                {"provider": "openrouter", "tokens": 1000, "cost": 0.01},
                {"provider": "openai", "tokens": 500, "cost": 0.005}
            ]
            mock_supabase.return_value = mock_supabase_response
            
            # Тестируем функцию
            result = await get_ai_usage(
                current_user={"id": "user123"}
            )
            
            # Проверяем результат
            assert result.total_tokens == 1500
            assert result.total_cost == 0.015
            assert len(result.usage_by_provider) == 2
            assert result.usage_by_provider[0].provider == "openrouter"
            assert result.usage_by_provider[0].tokens == 1000
    
    @pytest.mark.asyncio
    async def test_get_ai_usage_no_data(self):
        """Тест получения статистики использования AI без данных"""
        from backend.api.ai import get_ai_usage
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.execute_supabase_operation') as mock_supabase:
            # Настраиваем Supabase mock (пустые данные)
            mock_supabase_response = MagicMock()
            mock_supabase_response.data = []
            mock_supabase.return_value = mock_supabase_response
            
            # Тестируем функцию
            result = await get_ai_usage(
                current_user={"id": "user123"}
            )
            
            # Проверяем результат
            assert result.total_tokens == 0
            assert result.total_cost == 0.0
            assert len(result.usage_by_provider) == 0
    
    @pytest.mark.asyncio
    async def test_get_ai_providers_success(self):
        """Тест успешного получения списка AI провайдеров"""
        from backend.api.ai import get_ai_providers
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.get_ai_service') as mock_get_ai_service:
            # Настраиваем AI service mock
            mock_ai_service = MagicMock()
            mock_ai_service.get_available_providers.return_value = [
                {"name": "openrouter", "models": ["deepseek/deepseek-v3"]},
                {"name": "openai", "models": ["gpt-4", "gpt-3.5-turbo"]}
            ]
            mock_get_ai_service.return_value = mock_ai_service
            
            # Тестируем функцию
            result = await get_ai_providers(
                current_user={"id": "user123"}
            )
            
            # Проверяем результат
            assert len(result.providers) == 2
            assert result.providers[0]["name"] == "openrouter"
            assert result.providers[1]["name"] == "openai"
    
    @pytest.mark.asyncio
    async def test_validate_ai_keys_success(self):
        """Тест успешной валидации AI ключей"""
        from backend.api.ai import validate_ai_keys
        
        # Создаем mock request
        mock_request = MagicMock()
        mock_request.provider = "openrouter"
        mock_request.api_key = "sk-test1234567890abcdef"
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.get_ai_service') as mock_get_ai_service:
            # Настраиваем AI service mock
            mock_ai_service = MagicMock()
            mock_ai_service.validate_api_key = AsyncMock(return_value=True)
            mock_get_ai_service.return_value = mock_ai_service
            
            # Тестируем функцию
            result = await validate_ai_keys(
                request=mock_request,
                current_user={"id": "user123"}
            )
            
            # Проверяем результат
            assert result.valid is True
            assert result.message == "API key is valid"
    
    @pytest.mark.asyncio
    async def test_validate_ai_keys_invalid(self):
        """Тест валидации невалидного AI ключа"""
        from backend.api.ai import validate_ai_keys
        
        # Создаем mock request
        mock_request = MagicMock()
        mock_request.provider = "openrouter"
        mock_request.api_key = "invalid_key"
        
        # Настраиваем моки для зависимостей
        with patch('backend.api.ai.get_ai_service') as mock_get_ai_service:
            # Настраиваем AI service mock
            mock_ai_service = MagicMock()
            mock_ai_service.validate_api_key = AsyncMock(return_value=False)
            mock_get_ai_service.return_value = mock_ai_service
            
            # Тестируем функцию
            result = await validate_ai_keys(
                request=mock_request,
                current_user={"id": "user123"}
            )
            
            # Проверяем результат
            assert result.valid is False
            assert result.message == "API key is invalid"
    
    def test_ai_endpoints_imports(self):
        """Тест импортов AI endpoints"""
        # Проверяем, что все необходимые модули импортируются
        try:
            from backend.api.ai import (
                router, chat_with_ai, chat_with_ai_stream,
                get_ai_usage, get_ai_providers, validate_ai_keys
            )
            assert True  # Импорт успешен
        except ImportError as e:
            pytest.fail(f"Import failed: {e}")
    
    def test_ai_service_functions_exist(self):
        """Тест существования функций AI service"""
        from backend.services.ai_service import get_ai_service
        
        # Проверяем, что функция существует
        assert callable(get_ai_service)