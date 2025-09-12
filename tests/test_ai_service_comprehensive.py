"""
Комплексные тесты для AI Service
Покрывают все основные функции и сценарии
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime
from typing import Dict, List

from backend.services.ai_service import (
    AIService, AIProvider, AIRequest, AIResponse, AIProviderClient,
    OpenRouterClient, OpenAIClient, AnthropicClient, GroqClient,
    get_ai_service
)
from backend.core.exceptions import AIServiceError, NetworkError, ValidationError


class TestAIProvider:
    """Тесты для AIProvider enum"""
    
    def test_ai_provider_values(self):
        """Проверяем значения AIProvider"""
        assert AIProvider.OPENROUTER.value == "openrouter"
        assert AIProvider.OPENAI.value == "openai"
        assert AIProvider.ANTHROPIC.value == "anthropic"
        assert AIProvider.GROQ.value == "groq"
    
    def test_ai_provider_from_string(self):
        """Проверяем создание AIProvider из строки"""
        assert AIProvider("openrouter") == AIProvider.OPENROUTER
        assert AIProvider("openai") == AIProvider.OPENAI
        assert AIProvider("anthropic") == AIProvider.ANTHROPIC
        assert AIProvider("groq") == AIProvider.GROQ


class TestAIRequest:
    """Тесты для AIRequest dataclass"""
    
    def test_ai_request_creation(self):
        """Проверяем создание AIRequest"""
        messages = [{"role": "user", "content": "Hello"}]
        request = AIRequest(
            messages=messages,
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI,
            max_tokens=1000,
            temperature=0.5,
            user_id="user123",
            project_id="project456"
        )
        
        assert request.messages == messages
        assert request.model == "gpt-3.5-turbo"
        assert request.provider == AIProvider.OPENAI
        assert request.max_tokens == 1000
        assert request.temperature == 0.5
        assert request.user_id == "user123"
        assert request.project_id == "project456"
    
    def test_ai_request_defaults(self):
        """Проверяем значения по умолчанию"""
        messages = [{"role": "user", "content": "Hello"}]
        request = AIRequest(
            messages=messages,
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI
        )
        
        assert request.max_tokens == 4096
        assert request.temperature == 0.7
        assert request.user_id == ""
        assert request.project_id == ""


class TestAIResponse:
    """Тесты для AIResponse dataclass"""
    
    def test_ai_response_creation(self):
        """Проверяем создание AIResponse"""
        response = AIResponse(
            content="Hello, world!",
            tokens_used=10,
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI,
            response_time=1.5,
            cost_usd=0.001
        )
        
        assert response.content == "Hello, world!"
        assert response.tokens_used == 10
        assert response.model == "gpt-3.5-turbo"
        assert response.provider == AIProvider.OPENAI
        assert response.response_time == 1.5
        assert response.cost_usd == 0.001


class TestAIProviderClient:
    """Тесты для базового класса AIProviderClient"""
    
    def test_ai_provider_client_creation(self):
        """Проверяем создание AIProviderClient"""
        client = AIProviderClient("test_key", "test_model")
        assert client.api_key == "test_key"
        assert client.model == "test_model"
        assert client.provider == AIProvider.OPENROUTER  # default


class TestOpenRouterClient:
    """Тесты для OpenRouterClient"""
    
    def test_openrouter_client_creation(self):
        """Проверяем создание OpenRouterClient"""
        client = OpenRouterClient("test_key", "gpt-3.5-turbo")
        assert client.api_key == "test_key"
        assert client.model == "gpt-3.5-turbo"
        assert client.provider == AIProvider.OPENROUTER
    
    @pytest.mark.asyncio
    async def test_openrouter_client_chat_completion(self):
        """Тест chat completion для OpenRouter"""
        client = OpenRouterClient("test_key", "gpt-3.5-turbo")
        
        with patch('openai.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "Test response"
            mock_response.usage.total_tokens = 10
            
            mock_client.chat.completions.create.return_value = mock_response
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENROUTER
            )
            
            response = await client.chat_completion(request)
            
            assert response.content == "Test response"
            assert response.tokens_used == 10
            assert response.model == "gpt-3.5-turbo"
            assert response.provider == AIProvider.OPENROUTER
    
    @pytest.mark.asyncio
    async def test_openrouter_client_stream_completion(self):
        """Тест stream completion для OpenRouter"""
        client = OpenRouterClient("test_key", "gpt-3.5-turbo")
        
        with patch('openai.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            # Создаем mock stream
            mock_chunk1 = MagicMock()
            mock_chunk1.choices = [MagicMock()]
            mock_chunk1.choices[0].delta.content = "Hello"
            
            mock_chunk2 = MagicMock()
            mock_chunk2.choices = [MagicMock()]
            mock_chunk2.choices[0].delta.content = " world"
            
            mock_stream = [mock_chunk1, mock_chunk2]
            mock_client.chat.completions.create.return_value = mock_stream
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENROUTER
            )
            
            chunks = []
            async for chunk in client.stream_completion(request):
                chunks.append(chunk)
            
            assert len(chunks) == 2
            assert chunks[0] == "Hello"
            assert chunks[1] == " world"


class TestOpenAIClient:
    """Тесты для OpenAIClient"""
    
    def test_openai_client_creation(self):
        """Проверяем создание OpenAIClient"""
        client = OpenAIClient("test_key", "gpt-3.5-turbo")
        assert client.api_key == "test_key"
        assert client.model == "gpt-3.5-turbo"
        assert client.provider == AIProvider.OPENAI
    
    @pytest.mark.asyncio
    async def test_openai_client_chat_completion(self):
        """Тест chat completion для OpenAI"""
        client = OpenAIClient("test_key", "gpt-3.5-turbo")
        
        with patch('openai.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "OpenAI response"
            mock_response.usage.total_tokens = 15
            
            mock_client.chat.completions.create.return_value = mock_response
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            response = await client.chat_completion(request)
            
            assert response.content == "OpenAI response"
            assert response.tokens_used == 15
            assert response.provider == AIProvider.OPENAI


class TestAnthropicClient:
    """Тесты для AnthropicClient"""
    
    def test_anthropic_client_creation(self):
        """Проверяем создание AnthropicClient"""
        client = AnthropicClient("test_key", "claude-3-sonnet")
        assert client.api_key == "test_key"
        assert client.model == "claude-3-sonnet"
        assert client.provider == AIProvider.ANTHROPIC
    
    @pytest.mark.asyncio
    async def test_anthropic_client_chat_completion(self):
        """Тест chat completion для Anthropic"""
        client = AnthropicClient("test_key", "claude-3-sonnet")
        
        with patch('anthropic.AsyncAnthropic') as mock_anthropic:
            mock_client = AsyncMock()
            mock_anthropic.return_value = mock_client
            
            mock_response = MagicMock()
            mock_response.content = [MagicMock()]
            mock_response.content[0].text = "Anthropic response"
            mock_response.usage.input_tokens = 5
            mock_response.usage.output_tokens = 10
            
            mock_client.messages.create.return_value = mock_response
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="claude-3-sonnet",
                provider=AIProvider.ANTHROPIC
            )
            
            response = await client.chat_completion(request)
            
            assert response.content == "Anthropic response"
            assert response.tokens_used == 15  # input + output
            assert response.provider == AIProvider.ANTHROPIC


class TestGroqClient:
    """Тесты для GroqClient"""
    
    def test_groq_client_creation(self):
        """Проверяем создание GroqClient"""
        client = GroqClient("test_key", "llama-3-8b")
        assert client.api_key == "test_key"
        assert client.model == "llama-3-8b"
        assert client.provider == AIProvider.GROQ
    
    @pytest.mark.asyncio
    async def test_groq_client_chat_completion(self):
        """Тест chat completion для Groq"""
        client = GroqClient("test_key", "llama-3-8b")
        
        with patch('openai.AsyncOpenAI') as mock_openai:
            mock_client = AsyncMock()
            mock_openai.return_value = mock_client
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "Groq response"
            mock_response.usage.total_tokens = 20
            
            mock_client.chat.completions.create.return_value = mock_response
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="llama-3-8b",
                provider=AIProvider.GROQ
            )
            
            response = await client.chat_completion(request)
            
            assert response.content == "Groq response"
            assert response.tokens_used == 20
            assert response.provider == AIProvider.GROQ


class TestAIService:
    """Тесты для основного AIService"""
    
    def test_ai_service_creation(self):
        """Проверяем создание AIService"""
        user_api_keys = {
            "openai": "sk-test",
            "anthropic": "ant-test",
            "groq": "gsk-test"
        }
        
        service = AIService("user123", user_api_keys)
        
        assert service.user_id == "user123"
        assert service.user_api_keys == user_api_keys
        assert service.usage_stats == {}
        assert service.fallback_order == [
            AIProvider.OPENROUTER,
            AIProvider.OPENAI,
            AIProvider.ANTHROPIC,
            AIProvider.GROQ
        ]
    
    def test_ai_service_get_client(self):
        """Тест получения клиента для провайдера"""
        user_api_keys = {
            "openai": "sk-test",
            "anthropic": "ant-test"
        }
        
        service = AIService("user123", user_api_keys)
        
        # Тест OpenAI клиента
        openai_client = service._get_client(AIProvider.OPENAI, "gpt-3.5-turbo")
        assert isinstance(openai_client, OpenAIClient)
        assert openai_client.api_key == "sk-test"
        
        # Тест Anthropic клиента
        anthropic_client = service._get_client(AIProvider.ANTHROPIC, "claude-3-sonnet")
        assert isinstance(anthropic_client, AnthropicClient)
        assert anthropic_client.api_key == "ant-test"
    
    def test_ai_service_get_client_no_key(self):
        """Тест получения клиента без API ключа"""
        user_api_keys = {}
        service = AIService("user123", user_api_keys)
        
        with pytest.raises(AIServiceError, match="No API key found"):
            service._get_client(AIProvider.OPENAI, "gpt-3.5-turbo")
    
    @pytest.mark.asyncio
    async def test_ai_service_chat_completion_success(self):
        """Тест успешного chat completion"""
        user_api_keys = {"openai": "sk-test"}
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_response = AIResponse(
                content="Test response",
                tokens_used=10,
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI,
                response_time=1.0,
                cost_usd=0.001
            )
            mock_client.chat_completion.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            response = await service.chat_completion(request)
            
            assert response.content == "Test response"
            assert response.tokens_used == 10
            assert response.provider == AIProvider.OPENAI
    
    @pytest.mark.asyncio
    async def test_ai_service_chat_completion_with_fallback(self):
        """Тест chat completion с fallback"""
        user_api_keys = {
            "openai": "sk-test",
            "anthropic": "ant-test"
        }
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            # Первый клиент падает
            mock_client1 = AsyncMock()
            mock_client1.chat_completion.side_effect = NetworkError("Connection failed")
            
            # Второй клиент успешен
            mock_client2 = AsyncMock()
            mock_response = AIResponse(
                content="Fallback response",
                tokens_used=15,
                model="claude-3-sonnet",
                provider=AIProvider.ANTHROPIC,
                response_time=2.0,
                cost_usd=0.002
            )
            mock_client2.chat_completion.return_value = mock_response
            
            mock_get_client.side_effect = [mock_client1, mock_client2]
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            response = await service.chat_completion(request)
            
            assert response.content == "Fallback response"
            assert response.provider == AIProvider.ANTHROPIC
            assert mock_get_client.call_count == 2
    
    @pytest.mark.asyncio
    async def test_ai_service_chat_completion_all_fail(self):
        """Тест chat completion когда все провайдеры падают"""
        user_api_keys = {
            "openai": "sk-test",
            "anthropic": "ant-test"
        }
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_client.chat_completion.side_effect = NetworkError("All failed")
            mock_get_client.return_value = mock_client
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            with pytest.raises(AIServiceError, match="All providers failed"):
                await service.chat_completion(request)
    
    @pytest.mark.asyncio
    async def test_ai_service_stream_completion(self):
        """Тест stream completion"""
        user_api_keys = {"openai": "sk-test"}
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_stream = ["Hello", " world", "!"]
            mock_client.stream_completion.return_value = mock_stream.__aiter__()
            mock_get_client.return_value = mock_client
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            chunks = []
            async for chunk in service.stream_completion(request):
                chunks.append(chunk)
            
            assert chunks == ["Hello", " world", "!"]
    
    def test_ai_service_update_usage_stats(self):
        """Тест обновления статистики использования"""
        user_api_keys = {"openai": "sk-test"}
        service = AIService("user123", user_api_keys)
        
        response = AIResponse(
            content="Test",
            tokens_used=100,
            model="gpt-3.5-turbo",
            provider=AIProvider.OPENAI,
            response_time=1.0,
            cost_usd=0.01
        )
        
        service._update_usage_stats(response)
        
        assert "openai" in service.usage_stats
        assert service.usage_stats["openai"]["total_tokens"] == 100
        assert service.usage_stats["openai"]["total_cost"] == 0.01
        assert service.usage_stats["openai"]["request_count"] == 1
    
    def test_ai_service_get_usage_stats(self):
        """Тест получения статистики использования"""
        user_api_keys = {"openai": "sk-test"}
        service = AIService("user123", user_api_keys)
        
        # Добавляем статистику
        service.usage_stats = {
            "openai": {
                "total_tokens": 200,
                "total_cost": 0.02,
                "request_count": 2
            }
        }
        
        stats = service.get_usage_stats()
        
        assert stats["openai"]["total_tokens"] == 200
        assert stats["openai"]["total_cost"] == 0.02
        assert stats["openai"]["request_count"] == 2


class TestGetAIService:
    """Тесты для функции get_ai_service"""
    
    def test_get_ai_service(self):
        """Тест создания AIService через функцию"""
        user_api_keys = {
            "openai": "sk-test",
            "anthropic": "ant-test"
        }
        
        service = get_ai_service("user123", user_api_keys)
        
        assert isinstance(service, AIService)
        assert service.user_id == "user123"
        assert service.user_api_keys == user_api_keys


class TestAIServiceErrorHandling:
    """Тесты для обработки ошибок в AIService"""
    
    @pytest.mark.asyncio
    async def test_ai_service_validation_error(self):
        """Тест обработки ValidationError"""
        user_api_keys = {"openai": "sk-test"}
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_client.chat_completion.side_effect = ValidationError("Invalid request")
            mock_get_client.return_value = mock_client
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            with pytest.raises(ValidationError):
                await service.chat_completion(request)
    
    @pytest.mark.asyncio
    async def test_ai_service_timeout_error(self):
        """Тест обработки TimeoutError"""
        user_api_keys = {"openai": "sk-test"}
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_client.chat_completion.side_effect = TimeoutError("Request timeout")
            mock_get_client.return_value = mock_client
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            with pytest.raises(TimeoutError):
                await service.chat_completion(request)
    
    @pytest.mark.asyncio
    async def test_ai_service_network_error(self):
        """Тест обработки NetworkError"""
        user_api_keys = {"openai": "sk-test"}
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_client.chat_completion.side_effect = NetworkError("Network error")
            mock_get_client.return_value = mock_client
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI
            )
            
            with pytest.raises(NetworkError):
                await service.chat_completion(request)


class TestAIServiceIntegration:
    """Интеграционные тесты для AIService"""
    
    @pytest.mark.asyncio
    async def test_ai_service_full_workflow(self):
        """Тест полного рабочего процесса"""
        user_api_keys = {
            "openai": "sk-test",
            "anthropic": "ant-test"
        }
        service = AIService("user123", user_api_keys)
        
        with patch.object(service, '_get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_response = AIResponse(
                content="Full workflow response",
                tokens_used=50,
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI,
                response_time=1.5,
                cost_usd=0.005
            )
            mock_client.chat_completion.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-3.5-turbo",
                provider=AIProvider.OPENAI,
                user_id="user123",
                project_id="project456"
            )
            
            response = await service.chat_completion(request)
            
            # Проверяем ответ
            assert response.content == "Full workflow response"
            assert response.tokens_used == 50
            assert response.provider == AIProvider.OPENAI
            
            # Проверяем обновление статистики
            stats = service.get_usage_stats()
            assert "openai" in stats
            assert stats["openai"]["total_tokens"] == 50
            assert stats["openai"]["total_cost"] == 0.005
            assert stats["openai"]["request_count"] == 1