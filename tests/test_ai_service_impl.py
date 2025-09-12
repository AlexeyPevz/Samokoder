#!/usr/bin/env python3
"""
Тесты для AI Service Implementation
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from backend.services.implementations.ai_service_impl import AIServiceImpl


class TestAIServiceImpl:
    """Тесты для AIServiceImpl"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.ai_service_impl = AIServiceImpl()
    
    def test_init(self):
        """Тест инициализации AI Service Implementation"""
        assert self.ai_service_impl._ai_service is None
    
    def test_get_ai_service_first_call(self):
        """Тест получения AI сервиса при первом вызове"""
        with patch('backend.services.implementations.ai_service_impl.get_ai_service') as mock_get_service:
            mock_service = Mock()
            mock_get_service.return_value = mock_service
            
            result = self.ai_service_impl._get_ai_service()
            
            assert result == mock_service
            assert self.ai_service_impl._ai_service == mock_service
            mock_get_service.assert_called_once()
    
    def test_get_ai_service_cached(self):
        """Тест получения кэшированного AI сервиса"""
        mock_service = Mock()
        self.ai_service_impl._ai_service = mock_service
        
        with patch('backend.services.implementations.ai_service_impl.get_ai_service') as mock_get_service:
            result = self.ai_service_impl._get_ai_service()
            
            assert result == mock_service
            mock_get_service.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_chat_completion_success(self):
        """Тест успешного chat completion"""
        request = {"messages": [{"role": "user", "content": "Hello"}]}
        expected_response = {"content": "Hello! How can I help you?"}
        
        mock_ai_service = Mock()
        mock_ai_service.chat_completion = AsyncMock(return_value=expected_response)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service):
            result = await self.ai_service_impl.chat_completion(request)
            
            assert result == expected_response
            mock_ai_service.chat_completion.assert_called_once_with(request)
    
    @pytest.mark.asyncio
    async def test_chat_completion_error(self):
        """Тест chat completion с ошибкой"""
        request = {"messages": [{"role": "user", "content": "Hello"}]}
        error = Exception("AI service error")
        
        mock_ai_service = Mock()
        mock_ai_service.chat_completion = AsyncMock(side_effect=error)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service), \
             patch('backend.services.implementations.ai_service_impl.logger') as mock_logger:
            
            with pytest.raises(Exception, match="AI service error"):
                await self.ai_service_impl.chat_completion(request)
            
            mock_logger.error.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_chat_completion_stream_success(self):
        """Тест успешного streaming chat completion"""
        request = {"messages": [{"role": "user", "content": "Hello"}]}
        expected_chunks = [
            {"content": "Hello"},
            {"content": " there!"},
            {"content": " How can I help?"}
        ]
        
        mock_ai_service = Mock()
        
        async def mock_stream(request_param):
            for chunk in expected_chunks:
                yield chunk
        
        mock_ai_service.chat_completion_stream = mock_stream
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service):
            result_chunks = []
            async for chunk in self.ai_service_impl.chat_completion_stream(request):
                result_chunks.append(chunk)
            
            assert result_chunks == expected_chunks
    
    @pytest.mark.asyncio
    async def test_chat_completion_stream_error(self):
        """Тест streaming chat completion с ошибкой"""
        request = {"messages": [{"role": "user", "content": "Hello"}]}
        error = Exception("Streaming error")
        
        mock_ai_service = Mock()
        
        async def mock_stream_error(request_param):
            raise error
        
        mock_ai_service.chat_completion_stream = mock_stream_error
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service), \
             patch('backend.services.implementations.ai_service_impl.logger') as mock_logger:
            
            with pytest.raises(Exception, match="Streaming error"):
                async for chunk in self.ai_service_impl.chat_completion_stream(request):
                    pass
            
            mock_logger.error.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self):
        """Тест успешной валидации API ключа"""
        provider = "openai"
        api_key = "sk-test123"
        
        mock_ai_service = Mock()
        mock_ai_service.validate_api_key = AsyncMock(return_value=True)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service):
            result = await self.ai_service_impl.validate_api_key(provider, api_key)
            
            assert result is True
            mock_ai_service.validate_api_key.assert_called_once_with(provider, api_key)
    
    @pytest.mark.asyncio
    async def test_validate_api_key_failure(self):
        """Тест неуспешной валидации API ключа"""
        provider = "openai"
        api_key = "invalid-key"
        
        mock_ai_service = Mock()
        mock_ai_service.validate_api_key = AsyncMock(return_value=False)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service):
            result = await self.ai_service_impl.validate_api_key(provider, api_key)
            
            assert result is False
            mock_ai_service.validate_api_key.assert_called_once_with(provider, api_key)
    
    @pytest.mark.asyncio
    async def test_validate_api_key_error(self):
        """Тест валидации API ключа с ошибкой"""
        provider = "openai"
        api_key = "test-key"
        error = Exception("Network error")
        
        mock_ai_service = Mock()
        mock_ai_service.validate_api_key = AsyncMock(side_effect=error)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service), \
             patch('backend.services.implementations.ai_service_impl.logger') as mock_logger:
            
            result = await self.ai_service_impl.validate_api_key(provider, api_key)
            
            assert result is False
            mock_logger.error.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_usage_stats_success(self):
        """Тест успешного получения статистики использования"""
        provider = "openai"
        expected_stats = {
            "requests_count": 100,
            "tokens_used": 50000,
            "cost": 15.50
        }
        
        mock_ai_service = Mock()
        mock_ai_service.get_usage_stats = AsyncMock(return_value=expected_stats)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service):
            result = await self.ai_service_impl.get_usage_stats(provider)
            
            assert result == expected_stats
            mock_ai_service.get_usage_stats.assert_called_once_with(provider)
    
    @pytest.mark.asyncio
    async def test_get_usage_stats_error(self):
        """Тест получения статистики использования с ошибкой"""
        provider = "openai"
        error = Exception("Stats error")
        
        mock_ai_service = Mock()
        mock_ai_service.get_usage_stats = AsyncMock(side_effect=error)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service), \
             patch('backend.services.implementations.ai_service_impl.logger') as mock_logger:
            
            result = await self.ai_service_impl.get_usage_stats(provider)
            
            assert result == {}
            mock_logger.error.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_available_models_success(self):
        """Тест успешного получения доступных моделей"""
        provider = "openai"
        expected_models = ["gpt-3.5-turbo", "gpt-4", "gpt-4-turbo"]
        
        mock_ai_service = Mock()
        mock_ai_service.get_available_models = AsyncMock(return_value=expected_models)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service):
            result = await self.ai_service_impl.get_available_models(provider)
            
            assert result == expected_models
            mock_ai_service.get_available_models.assert_called_once_with(provider)
    
    @pytest.mark.asyncio
    async def test_get_available_models_error(self):
        """Тест получения доступных моделей с ошибкой"""
        provider = "openai"
        error = Exception("Models error")
        
        mock_ai_service = Mock()
        mock_ai_service.get_available_models = AsyncMock(side_effect=error)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service), \
             patch('backend.services.implementations.ai_service_impl.logger') as mock_logger:
            
            result = await self.ai_service_impl.get_available_models(provider)
            
            assert result == []
            mock_logger.error.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_estimate_cost_success(self):
        """Тест успешной оценки стоимости"""
        request = {
            "messages": [{"role": "user", "content": "Hello"}],
            "model": "gpt-3.5-turbo"
        }
        expected_cost = 0.0025
        
        mock_ai_service = Mock()
        mock_ai_service.estimate_cost = AsyncMock(return_value=expected_cost)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service):
            result = await self.ai_service_impl.estimate_cost(request)
            
            assert result == expected_cost
            mock_ai_service.estimate_cost.assert_called_once_with(request)
    
    @pytest.mark.asyncio
    async def test_estimate_cost_error(self):
        """Тест оценки стоимости с ошибкой"""
        request = {
            "messages": [{"role": "user", "content": "Hello"}],
            "model": "gpt-3.5-turbo"
        }
        error = Exception("Cost estimation error")
        
        mock_ai_service = Mock()
        mock_ai_service.estimate_cost = AsyncMock(side_effect=error)
        
        with patch.object(self.ai_service_impl, '_get_ai_service', return_value=mock_ai_service), \
             patch('backend.services.implementations.ai_service_impl.logger') as mock_logger:
            
            result = await self.ai_service_impl.estimate_cost(request)
            
            assert result == 0.0
            mock_logger.error.assert_called_once()