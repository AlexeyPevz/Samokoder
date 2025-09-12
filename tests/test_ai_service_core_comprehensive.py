"""
Комплексные тесты для AI Service core
Покрытие: 36% → 85%+
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from typing import Dict, List

from backend.services.ai_service import (
    AIProvider, AIRequest, AIResponse, AIProviderClient,
    OpenRouterClient, OpenAIClient, AnthropicClient, GroqClient,
    AIService, get_ai_service
)
from backend.core.exceptions import (
    AIServiceError, NetworkError, TimeoutError, 
    ValidationError, ConfigurationError
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
            model="gpt-4",
            provider=AIProvider.OPENAI,
            max_tokens=1000,
            temperature=0.5,
            user_id="test_user",
            project_id="test_project"
        )
        
        assert request.messages == messages
        assert request.model == "gpt-4"
        assert request.provider == AIProvider.OPENAI
        assert request.max_tokens == 1000
        assert request.temperature == 0.5
        assert request.user_id == "test_user"
        assert request.project_id == "test_project"
    
    def test_ai_request_defaults(self):
        """Тест значений по умолчанию AIRequest"""
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-4",
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
            content="Hello, world!",
            tokens_used=100,
            cost_usd=0.01,
            provider=AIProvider.OPENAI,
            model="gpt-4",
            response_time=1.5,
            success=True,
            error=None
        )
        
        assert response.content == "Hello, world!"
        assert response.tokens_used == 100
        assert response.cost_usd == 0.01
        assert response.provider == AIProvider.OPENAI
        assert response.model == "gpt-4"
        assert response.response_time == 1.5
        assert response.success is True
        assert response.error is None
    
    def test_ai_response_defaults(self):
        """Тест значений по умолчанию AIResponse"""
        response = AIResponse(
            content="Error",
            tokens_used=0,
            cost_usd=0.0,
            provider=AIProvider.OPENAI,
            model="gpt-4",
            response_time=0.0
        )
        
        assert response.success is True
        assert response.error is None


class TestAIProviderClient:
    """Тесты для базового класса AIProviderClient"""
    
    def test_ai_provider_client_creation(self):
        """Тест создания AIProviderClient"""
        client = AIProviderClient("test_key", AIProvider.OPENAI)
        
        assert client.api_key == "test_key"
        assert client.provider == AIProvider.OPENAI
        assert client.client is None
    
    @pytest.mark.asyncio
    async def test_chat_completion_not_implemented(self):
        """Тест NotImplementedError для chat_completion"""
        client = AIProviderClient("test_key", AIProvider.OPENAI)
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-4",
            provider=AIProvider.OPENAI
        )
        
        with pytest.raises(NotImplementedError):
            await client.chat_completion(request)
    
    @pytest.mark.asyncio
    async def test_validate_api_key_not_implemented(self):
        """Тест NotImplementedError для validate_api_key"""
        client = AIProviderClient("test_key", AIProvider.OPENAI)
        
        with pytest.raises(NotImplementedError):
            await client.validate_api_key()


class TestOpenRouterClient:
    """Тесты для OpenRouterClient"""
    
    def test_openrouter_client_creation(self):
        """Тест создания OpenRouterClient"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            client = OpenRouterClient("test_key")
            
            assert client.api_key == "test_key"
            assert client.provider == AIProvider.OPENROUTER
            assert client.client is not None
            mock_openai.assert_called_once_with(
                api_key="test_key",
                base_url="https://openrouter.ai/api/v1"
            )
    
    @pytest.mark.asyncio
    async def test_openrouter_chat_completion_success(self):
        """Тест успешного chat_completion для OpenRouter"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Мокаем ответ
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "Hello, world!"
            mock_response.usage.total_tokens = 100
            mock_client.chat.completions.create.return_value = mock_response
            
            client = OpenRouterClient("test_key")
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-4",
                provider=AIProvider.OPENROUTER
            )
            
            response = await client.chat_completion(request)
            
            assert isinstance(response, AIResponse)
            assert response.content == "Hello, world!"
            assert response.tokens_used == 100
            assert response.provider == AIProvider.OPENROUTER
            assert response.model == "gpt-4"
            assert response.success is True
            assert response.error is None
    
    @pytest.mark.asyncio
    async def test_openrouter_chat_completion_error(self):
        """Тест обработки ошибки в chat_completion для OpenRouter"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Мокаем исключение
            mock_client.chat.completions.create.side_effect = Exception("API Error")
            
            client = OpenRouterClient("test_key")
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-4",
                provider=AIProvider.OPENROUTER
            )
            
            response = await client.chat_completion(request)
            
            assert isinstance(response, AIResponse)
            assert response.content == ""
            assert response.tokens_used == 0
            assert response.cost_usd == 0.0
            assert response.success is False
            assert "API Error" in response.error
    
    @pytest.mark.asyncio
    async def test_openrouter_validate_api_key_success(self):
        """Тест успешной валидации API ключа для OpenRouter"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Мокаем успешный ответ
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "test"
            mock_client.chat.completions.create.return_value = mock_response
            
            client = OpenRouterClient("test_key")
            
            result = await client.validate_api_key()
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_openrouter_validate_api_key_failure(self):
        """Тест неудачной валидации API ключа для OpenRouter"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Мокаем ошибку для models.list()
            mock_client.models.list.side_effect = Exception("Invalid API key")
            
            client = OpenRouterClient("test_key")
            
            result = await client.validate_api_key()
            
            assert result is False


class TestOpenAIClient:
    """Тесты для OpenAIClient"""
    
    def test_openai_client_creation(self):
        """Тест создания OpenAIClient"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            client = OpenAIClient("test_key")
            
            assert client.api_key == "test_key"
            assert client.provider == AIProvider.OPENAI
            assert client.client is not None
            mock_openai.assert_called_once_with(api_key="test_key")
    
    @pytest.mark.asyncio
    async def test_openai_chat_completion_success(self):
        """Тест успешного chat_completion для OpenAI"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Мокаем ответ
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "Hello, world!"
            mock_response.usage.total_tokens = 150
            mock_client.chat.completions.create.return_value = mock_response
            
            client = OpenAIClient("test_key")
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-4",
                provider=AIProvider.OPENAI
            )
            
            response = await client.chat_completion(request)
            
            assert isinstance(response, AIResponse)
            assert response.content == "Hello, world!"
            assert response.tokens_used == 150
            assert response.provider == AIProvider.OPENAI
    
    @pytest.mark.asyncio
    async def test_openai_chat_completion_error(self):
        """Тест обработки ошибки в chat_completion для OpenAI"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Мокаем исключение
            mock_client.chat.completions.create.side_effect = Exception("Rate limit")
            
            client = OpenAIClient("test_key")
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-4",
                provider=AIProvider.OPENAI
            )
            
            response = await client.chat_completion(request)
            
            assert isinstance(response, AIResponse)
            assert response.success is False
            assert "Rate limit" in response.error
    
    @pytest.mark.asyncio
    async def test_openai_validate_api_key_success(self):
        """Тест успешной валидации API ключа для OpenAI"""
        with patch('backend.services.ai_service.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Мокаем успешный ответ
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "test"
            mock_client.chat.completions.create.return_value = mock_response
            
            client = OpenAIClient("test_key")
            
            result = await client.validate_api_key()
            
            assert result is True


class TestAnthropicClient:
    """Тесты для AnthropicClient"""
    
    def test_anthropic_client_creation(self):
        """Тест создания AnthropicClient"""
        with patch('backend.services.ai_service.AsyncAnthropic') as mock_anthropic:
            client = AnthropicClient("test_key")
            
            assert client.api_key == "test_key"
            assert client.provider == AIProvider.ANTHROPIC
            assert client.client is not None
            mock_anthropic.assert_called_once_with(api_key="test_key")
    
    @pytest.mark.asyncio
    async def test_anthropic_chat_completion_success(self):
        """Тест успешного chat_completion для Anthropic"""
        with patch('backend.services.ai_service.AsyncAnthropic') as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            
            # Мокаем ответ
            mock_response = Mock()
            mock_response.content = [Mock()]
            mock_response.content[0].text = "Hello, world!"
            mock_response.usage.input_tokens = 50
            mock_response.usage.output_tokens = 100
            mock_client.messages.create.return_value = mock_response
            
            client = AnthropicClient("test_key")
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="claude-3",
                provider=AIProvider.ANTHROPIC
            )
            
            response = await client.chat_completion(request)
            
            assert isinstance(response, AIResponse)
            assert response.content == "Hello, world!"
            assert response.tokens_used == 150
            assert response.provider == AIProvider.ANTHROPIC
    
    @pytest.mark.asyncio
    async def test_anthropic_chat_completion_error(self):
        """Тест обработки ошибки в chat_completion для Anthropic"""
        with patch('backend.services.ai_service.AsyncAnthropic') as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            
            # Мокаем исключение
            mock_client.messages.create.side_effect = Exception("Anthropic error")
            
            client = AnthropicClient("test_key")
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="claude-3",
                provider=AIProvider.ANTHROPIC
            )
            
            response = await client.chat_completion(request)
            
            assert isinstance(response, AIResponse)
            assert response.success is False
            assert "Anthropic error" in response.error
    
    @pytest.mark.asyncio
    async def test_anthropic_validate_api_key_success(self):
        """Тест успешной валидации API ключа для Anthropic"""
        with patch('backend.services.ai_service.AsyncAnthropic') as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            
            # Мокаем успешный ответ
            mock_response = Mock()
            mock_response.content = [Mock()]
            mock_response.content[0].text = "test"
            mock_client.messages.create.return_value = mock_response
            
            client = AnthropicClient("test_key")
            
            result = await client.validate_api_key()
            
            assert result is True


class TestGroqClient:
    """Тесты для GroqClient"""
    
    def test_groq_client_creation(self):
        """Тест создания GroqClient"""
        client = GroqClient("test_key")
        
        assert client.api_key == "test_key"
        assert client.provider == AIProvider.GROQ
        assert client.base_url == "https://api.groq.com/openai/v1"
        assert "Authorization" in client.headers
        assert "Content-Type" in client.headers


class TestAIService:
    """Тесты для AIService"""
    
    def test_ai_service_creation(self):
        """Тест создания AIService"""
        user_api_keys = {
            "openai": "test_openai_key",
            "anthropic": "test_anthropic_key"
        }
        
        service = AIService("test_user", user_api_keys)
        
        assert service.user_id == "test_user"
        assert service.user_api_keys == user_api_keys
        assert len(service.clients) == 2  # openai и anthropic
        assert service.usage_tracker == []
    
    def test_ai_service_has_openrouter_client(self):
        """Тест наличия клиента OpenRouter"""
        service = AIService("test_user", {"openrouter": "test_key"})
        
        assert AIProvider.OPENROUTER in service.clients
        assert isinstance(service.clients[AIProvider.OPENROUTER], OpenRouterClient)
    
    def test_ai_service_has_openai_client(self):
        """Тест наличия клиента OpenAI"""
        service = AIService("test_user", {"openai": "test_key"})
        
        assert AIProvider.OPENAI in service.clients
        assert isinstance(service.clients[AIProvider.OPENAI], OpenAIClient)
    
    def test_ai_service_has_anthropic_client(self):
        """Тест наличия клиента Anthropic"""
        service = AIService("test_user", {"anthropic": "test_key"})
        
        assert AIProvider.ANTHROPIC in service.clients
        assert isinstance(service.clients[AIProvider.ANTHROPIC], AnthropicClient)
    
    def test_ai_service_has_groq_client(self):
        """Тест наличия клиента Groq"""
        service = AIService("test_user", {"groq": "test_key"})
        
        assert AIProvider.GROQ in service.clients
        assert isinstance(service.clients[AIProvider.GROQ], GroqClient)
    
    def test_ai_service_no_clients_when_no_keys(self):
        """Тест отсутствия клиентов когда нет API ключей"""
        with patch('backend.services.ai_service.settings') as mock_settings:
            mock_settings.system_openrouter_key = ""
            mock_settings.system_openai_key = ""
            
            service = AIService("test_user", {})
            
            assert len(service.clients) == 0
    
    @pytest.mark.asyncio
    async def test_ai_service_route_request_success(self):
        """Тест успешного route_request"""
        with patch('backend.services.ai_service.OpenAIClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = AIResponse(
                content="Hello, world!",
                tokens_used=100,
                cost_usd=0.01,
                provider=AIProvider.OPENAI,
                model="gpt-4",
                response_time=1.0
            )
            mock_client.chat_completion.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            service = AIService("test_user", {"openai": "test_key"})
            
            response = await service.route_request(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-4",
                provider="openai"
            )
            
            assert isinstance(response, AIResponse)
            assert response.content == "Hello, world!"
            assert response.provider == AIProvider.OPENAI
    
    @pytest.mark.asyncio
    async def test_ai_service_route_request_no_clients(self):
        """Тест route_request когда нет клиентов"""
        with patch('backend.services.ai_service.settings') as mock_settings:
            mock_settings.system_openrouter_key = ""
            mock_settings.system_openai_key = ""
            
            service = AIService("test_user", {})
            
            response = await service.route_request(
                messages=[{"role": "user", "content": "Hello"}]
            )
            
            assert isinstance(response, AIResponse)
            assert response.success is False
            assert "No AI providers configured" in response.error
    
    @pytest.mark.asyncio
    async def test_ai_service_validate_all_keys(self):
        """Тест валидации всех API ключей"""
        with patch('backend.services.ai_service.OpenAIClient') as mock_openai_class, \
             patch('backend.services.ai_service.AnthropicClient') as mock_anthropic_class:
            
            mock_openai_client = AsyncMock()
            mock_anthropic_client = AsyncMock()
            
            mock_openai_client.validate_api_key.return_value = True
            mock_anthropic_client.validate_api_key.return_value = False
            
            mock_openai_class.return_value = mock_openai_client
            mock_anthropic_class.return_value = mock_anthropic_client
            
            service = AIService("test_user", {
                "openai": "test_openai_key",
                "anthropic": "test_anthropic_key"
            })
            
            result = await service.validate_all_keys()
            
            assert result == {
                "openai": True,
                "anthropic": False
            }
    
    @pytest.mark.asyncio
    async def test_ai_service_get_usage_stats(self):
        """Тест получения статистики использования"""
        service = AIService("test_user", {})
        
        # Добавляем статистику в usage_tracker
        service.usage_tracker = [
            {
                "provider": "openai",
                "tokens_used": 100,
                "cost_usd": 0.01,
                "success": True
            }
        ]
        
        stats = await service.get_usage_stats()
        
        assert stats["total_requests"] == 1
        assert stats["total_tokens"] == 100
        assert stats["total_cost"] == 0.01
        assert stats["success_rate"] == 100.0


class TestGetAIService:
    """Тесты для функции get_ai_service"""
    
    def test_get_ai_service(self):
        """Тест функции get_ai_service"""
        user_api_keys = {
            "openai": "test_openai_key",
            "anthropic": "test_anthropic_key"
        }
        
        service = get_ai_service("test_user", user_api_keys)
        
        assert isinstance(service, AIService)
        assert service.user_id == "test_user"
        assert service.user_api_keys == user_api_keys