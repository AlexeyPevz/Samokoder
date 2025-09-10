"""
Unit тесты для AI Service
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from backend.services.ai_service import (
    AIService, OpenRouterClient, OpenAIClient, AnthropicClient, GroqClient,
    AIProvider, AIRequest, AIResponse
)

class TestAIRequest:
    """Тесты для AIRequest"""
    
    def test_ai_request_creation(self):
        """Тест создания AIRequest"""
        messages = [{"role": "user", "content": "Hello"}]
        request = AIRequest(
            messages=messages,
            model="gpt-4o-mini",
            provider=AIProvider.OPENAI,
            max_tokens=1000,
            temperature=0.7,
            user_id="user123",
            project_id="project123"
        )
        
        assert request.messages == messages
        assert request.model == "gpt-4o-mini"
        assert request.provider == AIProvider.OPENAI
        assert request.max_tokens == 1000
        assert request.temperature == 0.7
        assert request.user_id == "user123"
        assert request.project_id == "project123"

class TestAIResponse:
    """Тесты для AIResponse"""
    
    def test_ai_response_creation(self):
        """Тест создания AIResponse"""
        response = AIResponse(
            content="Hello, I'm an AI assistant!",
            tokens_used=25,
            cost_usd=0.001,
            provider=AIProvider.OPENAI,
            model="gpt-4o-mini",
            response_time=1.5,
            success=True
        )
        
        assert response.content == "Hello, I'm an AI assistant!"
        assert response.tokens_used == 25
        assert response.cost_usd == 0.001
        assert response.provider == AIProvider.OPENAI
        assert response.model == "gpt-4o-mini"
        assert response.response_time == 1.5
        assert response.success is True
        assert response.error is None
    
    def test_ai_response_error(self):
        """Тест создания AIResponse с ошибкой"""
        response = AIResponse(
            content="",
            tokens_used=0,
            cost_usd=0.0,
            provider=AIProvider.OPENAI,
            model="gpt-4o-mini",
            response_time=0.5,
            success=False,
            error="API key invalid"
        )
        
        assert response.success is False
        assert response.error == "API key invalid"
        assert response.content == ""

class TestOpenRouterClient:
    """Тесты для OpenRouterClient"""
    
    @pytest.fixture
    def openrouter_client(self):
        """Фикстура для OpenRouterClient"""
        return OpenRouterClient("test-api-key")
    
    @pytest.mark.asyncio
    async def test_chat_completion_success(self, openrouter_client):
        """Тест успешного chat completion"""
        # Мокаем ответ от OpenAI API
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Hello, I'm an AI assistant!"
        mock_response.usage.total_tokens = 25
        
        openrouter_client.client.chat.completions.create = AsyncMock(return_value=mock_response)
        
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="deepseek/deepseek-v3",
            provider=AIProvider.OPENROUTER
        )
        
        response = await openrouter_client.chat_completion(request)
        
        assert response.success is True
        assert response.content == "Hello, I'm an AI assistant!"
        assert response.tokens_used == 25
        assert response.provider == AIProvider.OPENROUTER
    
    @pytest.mark.asyncio
    async def test_chat_completion_error(self, openrouter_client):
        """Тест ошибки chat completion"""
        # Мокаем ошибку
        openrouter_client.client.chat.completions.create = AsyncMock(
            side_effect=Exception("API error")
        )
        
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="deepseek/deepseek-v3",
            provider=AIProvider.OPENROUTER
        )
        
        response = await openrouter_client.chat_completion(request)
        
        assert response.success is False
        assert "API error" in response.error
        assert response.content == ""
    
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, openrouter_client):
        """Тест успешной валидации API ключа"""
        openrouter_client.client.models.list = AsyncMock(return_value=[])
        
        is_valid = await openrouter_client.validate_api_key()
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_validate_api_key_error(self, openrouter_client):
        """Тест ошибки валидации API ключа"""
        openrouter_client.client.models.list = AsyncMock(
            side_effect=Exception("Invalid API key")
        )
        
        is_valid = await openrouter_client.validate_api_key()
        assert is_valid is False
    
    def test_calculate_cost(self, openrouter_client):
        """Тест расчета стоимости"""
        # Тест бесплатной модели
        cost = openrouter_client._calculate_cost(1000, "deepseek/deepseek-v3")
        assert cost == 0.0
        
        # Тест неизвестной модели
        cost = openrouter_client._calculate_cost(1000, "unknown/model")
        assert cost == 0.0

class TestOpenAIClient:
    """Тесты для OpenAIClient"""
    
    @pytest.fixture
    def openai_client(self):
        """Фикстура для OpenAIClient"""
        return OpenAIClient("test-api-key")
    
    @pytest.mark.asyncio
    async def test_chat_completion_success(self, openai_client):
        """Тест успешного chat completion"""
        # Мокаем ответ от OpenAI API
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Hello from OpenAI!"
        mock_response.usage.total_tokens = 30
        
        openai_client.client.chat.completions.create = AsyncMock(return_value=mock_response)
        
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-4o-mini",
            provider=AIProvider.OPENAI
        )
        
        response = await openai_client.chat_completion(request)
        
        assert response.success is True
        assert response.content == "Hello from OpenAI!"
        assert response.tokens_used == 30
        assert response.provider == AIProvider.OPENAI
    
    def test_calculate_cost(self, openai_client):
        """Тест расчета стоимости"""
        # Тест gpt-4o-mini
        cost = openai_client._calculate_cost(1000, "gpt-4o-mini")
        assert cost == 0.15  # $0.15 per 1K tokens
        
        # Тест gpt-4o
        cost = openai_client._calculate_cost(1000, "gpt-4o")
        assert cost == 5.0  # $5 per 1K tokens
        
        # Тест неизвестной модели
        cost = openai_client._calculate_cost(1000, "unknown-model")
        assert cost == 0.0

class TestAnthropicClient:
    """Тесты для AnthropicClient"""
    
    @pytest.fixture
    def anthropic_client(self):
        """Фикстура для AnthropicClient"""
        return AnthropicClient("test-api-key")
    
    @pytest.mark.asyncio
    async def test_chat_completion_success(self, anthropic_client):
        """Тест успешного chat completion"""
        # Мокаем ответ от Anthropic API
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = "Hello from Claude!"
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 15
        
        anthropic_client.client.messages.create = AsyncMock(return_value=mock_response)
        
        request = AIRequest(
            messages=[
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": "Hello"}
            ],
            model="claude-3-haiku-20240307",
            provider=AIProvider.ANTHROPIC
        )
        
        response = await anthropic_client.chat_completion(request)
        
        assert response.success is True
        assert response.content == "Hello from Claude!"
        assert response.tokens_used == 25  # 10 + 15
        assert response.provider == AIProvider.ANTHROPIC
    
    def test_calculate_cost(self, anthropic_client):
        """Тест расчета стоимости"""
        # Тест claude-3-haiku
        cost = anthropic_client._calculate_cost(1000, "claude-3-haiku-20240307")
        assert cost == 0.25  # $0.25 per 1K tokens
        
        # Тест claude-3-sonnet
        cost = anthropic_client._calculate_cost(1000, "claude-3-sonnet-20240229")
        assert cost == 3.0  # $3 per 1K tokens

class TestGroqClient:
    """Тесты для GroqClient"""
    
    @pytest.fixture
    def groq_client(self):
        """Фикстура для GroqClient"""
        return GroqClient("test-api-key")
    
    @pytest.mark.asyncio
    async def test_chat_completion_success(self, groq_client):
        """Тест успешного chat completion"""
        # Мокаем ответ от Groq API
        mock_response_data = {
            "choices": [{"message": {"content": "Hello from Groq!"}}],
            "usage": {"total_tokens": 20}
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_response_data
            mock_response.raise_for_status.return_value = None
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            request = AIRequest(
                messages=[{"role": "user", "content": "Hello"}],
                model="llama-3-8b-8192",
                provider=AIProvider.GROQ
            )
            
            response = await groq_client.chat_completion(request)
            
            assert response.success is True
            assert response.content == "Hello from Groq!"
            assert response.tokens_used == 20
            assert response.cost_usd == 0.0  # Groq бесплатный
            assert response.provider == AIProvider.GROQ

class TestAIService:
    """Тесты для AIService"""
    
    @pytest.fixture
    def ai_service(self):
        """Фикстура для AIService"""
        user_api_keys = {
            "openai": "sk-test-openai-key",
            "anthropic": "sk-ant-test-anthropic-key"
        }
        return AIService("user123", user_api_keys)
    
    def test_initialization(self, ai_service):
        """Тест инициализации AIService"""
        assert ai_service.user_id == "user123"
        assert ai_service.user_api_keys == {
            "openai": "sk-test-openai-key",
            "anthropic": "sk-ant-test-anthropic-key"
        }
        assert len(ai_service.clients) == 2
        assert AIProvider.OPENAI in ai_service.clients
        assert AIProvider.ANTHROPIC in ai_service.clients
    
    def test_select_best_provider(self, ai_service):
        """Тест выбора лучшего провайдера"""
        # OpenRouter должен быть приоритетным
        provider = ai_service._select_best_provider()
        assert provider == AIProvider.OPENAI  # Первый доступный
    
    def test_get_default_model_for_provider(self, ai_service):
        """Тест получения модели по умолчанию"""
        model = ai_service._get_default_model_for_provider(AIProvider.OPENAI)
        assert model == "gpt-4o-mini"
        
        model = ai_service._get_default_model_for_provider(AIProvider.ANTHROPIC)
        assert model == "claude-3-haiku-20240307"
    
    @pytest.mark.asyncio
    async def test_route_request_success(self, ai_service):
        """Тест успешного маршрутизированного запроса"""
        # Мокаем клиент
        mock_client = AsyncMock()
        mock_response = AIResponse(
            content="Test response",
            tokens_used=10,
            cost_usd=0.001,
            provider=AIProvider.OPENAI,
            model="gpt-4o-mini",
            response_time=1.0
        )
        mock_client.chat_completion.return_value = mock_response
        ai_service.clients[AIProvider.OPENAI] = mock_client
        
        messages = [{"role": "user", "content": "Test message"}]
        response = await ai_service.route_request(messages)
        
        assert response.success is True
        assert response.content == "Test response"
        assert response.provider == AIProvider.OPENAI
    
    @pytest.mark.asyncio
    async def test_route_request_no_providers(self):
        """Тест запроса без доступных провайдеров"""
        ai_service = AIService("user123", {})
        
        messages = [{"role": "user", "content": "Test message"}]
        response = await ai_service.route_request(messages)
        
        assert response.success is False
        assert "No AI providers configured" in response.error
    
    @pytest.mark.asyncio
    async def test_fallback_request(self, ai_service):
        """Тест fallback запроса"""
        # Мокаем первый клиент с ошибкой
        mock_client1 = AsyncMock()
        mock_client1.chat_completion.side_effect = Exception("First client error")
        
        # Мокаем второй клиент с успехом
        mock_client2 = AsyncMock()
        mock_response = AIResponse(
            content="Fallback response",
            tokens_used=10,
            cost_usd=0.001,
            provider=AIProvider.ANTHROPIC,
            model="claude-3-haiku-20240307",
            response_time=1.0
        )
        mock_client2.chat_completion.return_value = mock_response
        
        ai_service.clients[AIProvider.OPENAI] = mock_client1
        ai_service.clients[AIProvider.ANTHROPIC] = mock_client2
        
        request = AIRequest(
            messages=[{"role": "user", "content": "Test message"}],
            model="gpt-4o-mini",
            provider=AIProvider.OPENAI
        )
        
        response = await ai_service._fallback_request(request)
        
        assert response.success is True
        assert response.content == "Fallback response"
        assert response.provider == AIProvider.ANTHROPIC
    
    @pytest.mark.asyncio
    async def test_validate_all_keys(self, ai_service):
        """Тест валидации всех ключей"""
        # Мокаем клиенты
        mock_client1 = AsyncMock()
        mock_client1.validate_api_key.return_value = True
        
        mock_client2 = AsyncMock()
        mock_client2.validate_api_key.return_value = False
        
        ai_service.clients[AIProvider.OPENAI] = mock_client1
        ai_service.clients[AIProvider.ANTHROPIC] = mock_client2
        
        results = await ai_service.validate_all_keys()
        
        assert results["openai"] is True
        assert results["anthropic"] is False
    
    @pytest.mark.asyncio
    async def test_get_usage_stats(self, ai_service):
        """Тест получения статистики использования"""
        # Добавляем тестовые записи
        ai_service.usage_tracker = [
            {
                "timestamp": "2025-01-01T00:00:00Z",
                "user_id": "user123",
                "provider": "openai",
                "model": "gpt-4o-mini",
                "tokens_used": 100,
                "cost_usd": 0.01,
                "success": True
            },
            {
                "timestamp": "2025-01-01T00:01:00Z",
                "user_id": "user123",
                "provider": "anthropic",
                "model": "claude-3-haiku-20240307",
                "tokens_used": 50,
                "cost_usd": 0.005,
                "success": True
            }
        ]
        
        stats = await ai_service.get_usage_stats()
        
        assert stats["total_requests"] == 2
        assert stats["total_tokens"] == 150
        assert stats["total_cost"] == 0.015
        assert stats["success_rate"] == 100.0
        assert "openai" in stats["providers"]
        assert "anthropic" in stats["providers"]