#!/usr/bin/env python3
"""
Функциональные тесты для AI Service модуля
Реальные тесты, которые выполняют код и увеличивают покрытие
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
import json

from backend.services.ai_service import (
    AIProvider, AIRequest, AIResponse, AIProviderClient,
    OpenRouterClient, OpenAIClient, AnthropicClient, GroqClient, AIService
)


class TestAIProvider:
    """Тесты для AIProvider enum"""
    
    def test_ai_provider_values(self):
        """Тест значений AIProvider"""
        assert AIProvider.OPENROUTER.value == "openrouter"
        assert AIProvider.OPENAI.value == "openai"
        assert AIProvider.ANTHROPIC.value == "anthropic"
        assert AIProvider.GROQ.value == "groq"


class TestAIRequest:
    """Тесты для AIRequest dataclass"""
    
    def test_ai_request_creation(self):
        """Тест создания AIRequest"""
        messages = [{"role": "user", "content": "Hello"}]
        request = AIRequest(
            messages=messages,
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI,
            max_tokens=1000,
            temperature=0.8,
            user_id="user123",
            project_id="proj456"
        )
        
        assert request.messages == messages
        assert request.model == "gpt-3.5-turbo"
        assert request.provider == AIProvider.OPENAI
        assert request.max_tokens == 1000
        assert request.temperature == 0.8
        assert request.user_id == "user123"
        assert request.project_id == "proj456"
    
    def test_ai_request_defaults(self):
        """Тест значений по умолчанию для AIRequest"""
        messages = [{"role": "user", "content": "Test"}]
        request = AIRequest(
            messages=messages,
            model="test-model",
            provider=AIProvider.OPENAI
        )
        
        assert request.max_tokens == 4096
        assert request.temperature == 0.7
        assert request.user_id == ""
        assert request.project_id == ""


class TestAIResponse:
    """Тесты для AIResponse dataclass"""
    
    def test_ai_response_creation(self):
        """Тест создания AIResponse"""
        response = AIResponse(
            content="Hello world",
            tokens_used=100,
            cost_usd=0.001,
            provider=AIProvider.OPENAI,
            model="gpt-3.5-turbo",
            response_time=1.5
        )
        
        assert response.content == "Hello world"
        assert response.tokens_used == 100
        assert response.cost_usd == 0.001
        assert response.provider == AIProvider.OPENAI
        assert response.model == "gpt-3.5-turbo"
        assert response.response_time == 1.5
        assert response.success is True
        assert response.error is None
    
    def test_ai_response_with_error(self):
        """Тест создания AIResponse с ошибкой"""
        response = AIResponse(
            content="",
            tokens_used=0,
            cost_usd=0.0,
            provider=AIProvider.OPENAI,
            model="gpt-3.5-turbo",
            response_time=0.5,
            success=False,
            error="API key invalid"
        )
        
        assert response.success is False
        assert response.error == "API key invalid"


class TestAIProviderClient:
    """Тесты для AIProviderClient"""
    
    def test_ai_provider_client_creation(self):
        """Тест создания AIProviderClient"""
        client = AIProviderClient("test-key", AIProvider.OPENAI)
        
        assert client.api_key == "test-key"
        assert client.provider == AIProvider.OPENAI
        assert client.client is None
    
    @pytest.mark.asyncio
    async def test_ai_provider_client_chat_completion_not_implemented(self):
        """Тест что chat_completion не реализован в базовом классе"""
        client = AIProviderClient("test-key", AIProvider.OPENAI)
        request = AIRequest(
            messages=[{"role": "user", "content": "test"}],
            model="test-model",
            provider=AIProvider.OPENAI
        )
        
        with pytest.raises(NotImplementedError):
            await client.chat_completion(request)
    
    @pytest.mark.asyncio
    async def test_ai_provider_client_validate_api_key_not_implemented(self):
        """Тест что validate_api_key не реализован в базовом классе"""
        client = AIProviderClient("test-key", AIProvider.OPENAI)
        
        with pytest.raises(NotImplementedError):
            await client.validate_api_key()


class TestOpenRouterClient:
    """Тесты для OpenRouterClient"""
    
    @patch('backend.services.ai_service.AsyncOpenAI')
    def test_openrouter_client_creation(self, mock_openai):
        """Тест создания OpenRouterClient"""
        client = OpenRouterClient("test-key")
        
        assert client.api_key == "test-key"
        assert client.provider == AIProvider.OPENROUTER
        mock_openai.assert_called_once_with(
            api_key="test-key",
            base_url="https://openrouter.ai/api/v1"
        )
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncOpenAI')
    async def test_openrouter_client_chat_completion_success(self, mock_openai):
        """Тест успешного chat_completion для OpenRouter"""
        # Настройка мока
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Hello from OpenRouter"
        mock_response.usage.total_tokens = 50
        
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai.return_value = mock_client
        
        client = OpenRouterClient("test-key")
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="openrouter/anthropic/claude-3-haiku",
            provider=AIProvider.OPENROUTER
        )
        
        response = await client.chat_completion(request)
        
        assert response.content == "Hello from OpenRouter"
        assert response.tokens_used == 50
        assert response.provider == AIProvider.OPENROUTER
        assert response.model == "openrouter/anthropic/claude-3-haiku"
        assert response.success is True
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncOpenAI')
    async def test_openrouter_client_chat_completion_error(self, mock_openai):
        """Тест ошибки в chat_completion для OpenRouter"""
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(side_effect=Exception("API Error"))
        mock_openai.return_value = mock_client
        
        client = OpenRouterClient("test-key")
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="test-model",
            provider=AIProvider.OPENROUTER
        )
        
        response = await client.chat_completion(request)
        
        assert response.success is False
        assert "API Error" in response.error
        assert response.content == ""
        assert response.tokens_used == 0
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncOpenAI')
    async def test_openrouter_client_validate_api_key_success(self, mock_openai):
        """Тест успешной валидации API ключа для OpenRouter"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Valid"
        
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai.return_value = mock_client
        
        client = OpenRouterClient("test-key")
        
        result = await client.validate_api_key()
        
        assert result is True
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncOpenAI')
    async def test_openrouter_client_validate_api_key_failure(self, mock_openai):
        """Тест неуспешной валидации API ключа для OpenRouter"""
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(side_effect=Exception("Invalid key"))
        mock_openai.return_value = mock_client
        
        client = OpenRouterClient("test-key")
        
        result = await client.validate_api_key()
        
        assert result is False


class TestOpenAIClient:
    """Тесты для OpenAIClient"""
    
    @patch('backend.services.ai_service.AsyncOpenAI')
    def test_openai_client_creation(self, mock_openai):
        """Тест создания OpenAIClient"""
        client = OpenAIClient("test-key")
        
        assert client.api_key == "test-key"
        assert client.provider == AIProvider.OPENAI
        mock_openai.assert_called_once_with(api_key="test-key")
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncOpenAI')
    async def test_openai_client_chat_completion_success(self, mock_openai):
        """Тест успешного chat_completion для OpenAI"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Hello from OpenAI"
        mock_response.usage.total_tokens = 75
        
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai.return_value = mock_client
        
        client = OpenAIClient("test-key")
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI
        )
        
        response = await client.chat_completion(request)
        
        assert response.content == "Hello from OpenAI"
        assert response.tokens_used == 75
        assert response.provider == AIProvider.OPENAI
        assert response.model == "gpt-3.5-turbo"
        assert response.success is True
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncOpenAI')
    async def test_openai_client_validate_api_key_success(self, mock_openai):
        """Тест успешной валидации API ключа для OpenAI"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Valid"
        
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai.return_value = mock_client
        
        client = OpenAIClient("test-key")
        
        result = await client.validate_api_key()
        
        assert result is True


class TestAnthropicClient:
    """Тесты для AnthropicClient"""
    
    @patch('backend.services.ai_service.AsyncAnthropic')
    def test_anthropic_client_creation(self, mock_anthropic):
        """Тест создания AnthropicClient"""
        client = AnthropicClient("test-key")
        
        assert client.api_key == "test-key"
        assert client.provider == AIProvider.ANTHROPIC
        mock_anthropic.assert_called_once_with(api_key="test-key")
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncAnthropic')
    async def test_anthropic_client_chat_completion_success(self, mock_anthropic):
        """Тест успешного chat_completion для Anthropic"""
        mock_response = Mock()
        mock_response.content = [Mock()]
        mock_response.content[0].text = "Hello from Anthropic"
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 20
        
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_anthropic.return_value = mock_client
        
        client = AnthropicClient("test-key")
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="claude-3-haiku-20240307",
            provider=AIProvider.ANTHROPIC
        )
        
        response = await client.chat_completion(request)
        
        assert response.content == "Hello from Anthropic"
        assert response.tokens_used == 30  # input + output
        assert response.provider == AIProvider.ANTHROPIC
        assert response.model == "claude-3-haiku-20240307"
        assert response.success is True
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.AsyncAnthropic')
    async def test_anthropic_client_validate_api_key_success(self, mock_anthropic):
        """Тест успешной валидации API ключа для Anthropic"""
        mock_response = Mock()
        mock_response.content = [Mock()]
        mock_response.content[0].text = "Valid"
        
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_anthropic.return_value = mock_client
        
        client = AnthropicClient("test-key")
        
        result = await client.validate_api_key()
        
        assert result is True


class TestGroqClient:
    """Тесты для GroqClient"""
    
    @patch('backend.services.ai_service.httpx.AsyncClient')
    def test_groq_client_creation(self, mock_httpx):
        """Тест создания GroqClient"""
        client = GroqClient("test-key")
        
        assert client.api_key == "test-key"
        assert client.provider == AIProvider.GROQ
        mock_httpx.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.httpx.AsyncClient')
    async def test_groq_client_chat_completion_success(self, mock_httpx):
        """Тест успешного chat_completion для Groq"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Hello from Groq"}}],
            "usage": {"total_tokens": 60}
        }
        
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_httpx.return_value = mock_client
        
        client = GroqClient("test-key")
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="llama2-70b-4096",
            provider=AIProvider.GROQ
        )
        
        response = await client.chat_completion(request)
        
        assert response.content == "Hello from Groq"
        assert response.tokens_used == 60
        assert response.provider == AIProvider.GROQ
        assert response.model == "llama2-70b-4096"
        assert response.success is True
    
    @pytest.mark.asyncio
    @patch('backend.services.ai_service.httpx.AsyncClient')
    async def test_groq_client_validate_api_key_success(self, mock_httpx):
        """Тест успешной валидации API ключа для Groq"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Valid"}}]
        }
        
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_httpx.return_value = mock_client
        
        client = GroqClient("test-key")
        
        result = await client.validate_api_key()
        
        assert result is True


class TestAIService:
    """Тесты для AIService"""
    
    def test_ai_service_creation(self):
        """Тест создания AIService"""
        service = AIService()
        
        assert service is not None
        assert hasattr(service, 'clients')
        assert hasattr(service, 'usage_tracker')
    
    @pytest.mark.asyncio
    async def test_ai_service_chat_completion_success(self):
        """Тест успешного chat_completion через AIService"""
        # Создаем мок клиента
        mock_client = AsyncMock()
        mock_response = AIResponse(
            content="Test response",
            tokens_used=100,
            cost_usd=0.001,
            provider=AIProvider.OPENAI,
            model="gpt-3.5-turbo",
            response_time=1.0
        )
        mock_client.chat_completion.return_value = mock_response
        
        service = AIService()
        service.clients[AIProvider.OPENAI] = mock_client
        
        request = AIRequest(
            messages=[{"role": "user", "content": "Test"}],
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI
        )
        
        response = await service.chat_completion(request)
        
        assert response.content == "Test response"
        assert response.success is True
        mock_client.chat_completion.assert_called_once_with(request)
    
    @pytest.mark.asyncio
    async def test_ai_service_chat_completion_fallback(self):
        """Тест fallback механизма в AIService"""
        # Создаем мок клиентов
        mock_primary = AsyncMock()
        mock_primary.chat_completion.side_effect = Exception("Primary failed")
        
        mock_fallback = AsyncMock()
        mock_response = AIResponse(
            content="Fallback response",
            tokens_used=50,
            cost_usd=0.0005,
            provider=AIProvider.OPENROUTER,
            model="test-model",
            response_time=0.5
        )
        mock_fallback.chat_completion.return_value = mock_response
        
        service = AIService()
        service.clients[AIProvider.OPENAI] = mock_primary
        service.clients[AIProvider.OPENROUTER] = mock_fallback
        
        request = AIRequest(
            messages=[{"role": "user", "content": "Test"}],
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI
        )
        
        response = await service.chat_completion(request)
        
        assert response.content == "Fallback response"
        assert response.success is True
        assert response.provider == AIProvider.OPENROUTER
    
    @pytest.mark.asyncio
    async def test_ai_service_validate_api_key(self):
        """Тест валидации API ключей через AIService"""
        mock_client = AsyncMock()
        mock_client.validate_api_key.return_value = True
        
        service = AIService()
        service.clients[AIProvider.OPENAI] = mock_client
        
        result = await service.validate_api_key(AIProvider.OPENAI)
        
        assert result is True
        mock_client.validate_api_key.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_ai_service_get_usage_stats(self):
        """Тест получения статистики использования"""
        service = AIService()
        
        # Добавляем некоторые данные в usage_tracker
        service.usage_tracker["user123"] = {
            "total_tokens": 1000,
            "total_cost": 0.01,
            "requests": 5
        }
        
        stats = await service.get_usage_stats("user123")
        
        assert stats["total_tokens"] == 1000
        assert stats["total_cost"] == 0.01
        assert stats["requests"] == 5
    
    @pytest.mark.asyncio
    async def test_ai_service_get_usage_stats_no_data(self):
        """Тест получения статистики для пользователя без данных"""
        service = AIService()
        
        stats = await service.get_usage_stats("nonexistent_user")
        
        assert stats["total_tokens"] == 0
        assert stats["total_cost"] == 0.0
        assert stats["requests"] == 0


class TestAIServiceIntegration:
    """Интеграционные тесты для AIService"""
    
    @pytest.mark.asyncio
    async def test_ai_service_multiple_requests(self):
        """Тест множественных запросов"""
        service = AIService()
        
        # Создаем мок клиента
        mock_client = AsyncMock()
        mock_response = AIResponse(
            content="Response",
            tokens_used=100,
            cost_usd=0.001,
            provider=AIProvider.OPENAI,
            model="gpt-3.5-turbo",
            response_time=1.0
        )
        mock_client.chat_completion.return_value = mock_response
        service.clients[AIProvider.OPENAI] = mock_client
        
        # Создаем несколько запросов
        requests = []
        for i in range(3):
            request = AIRequest(
                messages=[{"role": "user", "content": f"Test {i}"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI,
                user_id=f"user{i}"
            )
            requests.append(request)
        
        # Выполняем запросы параллельно
        responses = await asyncio.gather(*[
            service.chat_completion(req) for req in requests
        ])
        
        assert len(responses) == 3
        for response in responses:
            assert response.success is True
            assert response.content == "Response"
    
    @pytest.mark.asyncio
    async def test_ai_service_error_handling(self):
        """Тест обработки ошибок"""
        service = AIService()
        
        # Создаем мок клиента, который всегда падает
        mock_client = AsyncMock()
        mock_client.chat_completion.side_effect = Exception("Service unavailable")
        service.clients[AIProvider.OPENAI] = mock_client
        
        request = AIRequest(
            messages=[{"role": "user", "content": "Test"}],
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI
        )
        
        response = await service.chat_completion(request)
        
        assert response.success is False
        assert "Service unavailable" in response.error
        assert response.content == ""
        assert response.tokens_used == 0


class TestAIServiceCostCalculation:
    """Тесты для расчета стоимости"""
    
    def test_openrouter_cost_calculation(self):
        """Тест расчета стоимости для OpenRouter"""
        client = OpenRouterClient("test-key")
        
        # Тестируем разные модели
        cost1 = client._calculate_cost(1000, "openrouter/anthropic/claude-3-haiku")
        cost2 = client._calculate_cost(1000, "openrouter/meta-llama/llama-2-70b-chat")
        
        assert cost1 > 0
        assert cost2 > 0
        assert cost1 != cost2  # Разные модели должны иметь разную стоимость
    
    def test_openai_cost_calculation(self):
        """Тест расчета стоимости для OpenAI"""
        client = OpenAIClient("test-key")
        
        cost = client._calculate_cost(1000, "gpt-3.5-turbo")
        assert cost > 0
        
        cost2 = client._calculate_cost(1000, "gpt-4")
        assert cost2 > cost  # GPT-4 должен быть дороже
    
    def test_anthropic_cost_calculation(self):
        """Тест расчета стоимости для Anthropic"""
        client = AnthropicClient("test-key")
        
        cost = client._calculate_cost(1000, "claude-3-haiku-20240307")
        assert cost > 0
        
        cost2 = client._calculate_cost(1000, "claude-3-opus-20240229")
        assert cost2 > cost  # Opus должен быть дороже Haiku
    
    def test_groq_cost_calculation(self):
        """Тест расчета стоимости для Groq"""
        client = GroqClient("test-key")
        
        cost = client._calculate_cost(1000, "llama2-70b-4096")
        assert cost > 0
        
        cost2 = client._calculate_cost(1000, "mixtral-8x7b-32768")
        assert cost2 > 0
