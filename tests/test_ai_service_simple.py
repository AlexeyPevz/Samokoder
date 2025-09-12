"""
Упрощенные тесты для AI Service (26% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio
from datetime import datetime

from backend.services.ai_service import (
    AIProvider,
    AIRequest,
    AIResponse,
    AIService
)


class TestAIProvider:
    """Тесты для AIProvider enum"""

    def test_enum_values(self):
        """Тест значений enum"""
        assert AIProvider.OPENROUTER.value == "openrouter"
        assert AIProvider.OPENAI.value == "openai"
        assert AIProvider.ANTHROPIC.value == "anthropic"
        assert AIProvider.GROQ.value == "groq"


class TestAIRequest:
    """Тесты для AIRequest"""

    def test_init_default(self):
        """Тест инициализации с параметрами по умолчанию"""
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-4",
            provider=AIProvider.OPENAI
        )
        
        assert request.messages == [{"role": "user", "content": "Hello"}]
        assert request.model == "gpt-4"
        assert request.provider == AIProvider.OPENAI
        assert request.max_tokens == 4096
        assert request.temperature == 0.7
        assert request.user_id == ""
        assert request.project_id == ""

    def test_init_custom(self):
        """Тест инициализации с кастомными параметрами"""
        request = AIRequest(
            messages=[{"role": "user", "content": "Hello"}],
            model="claude-3",
            provider=AIProvider.ANTHROPIC,
            max_tokens=2048,
            temperature=0.5,
            user_id="user123",
            project_id="project456"
        )
        
        assert request.max_tokens == 2048
        assert request.temperature == 0.5
        assert request.user_id == "user123"
        assert request.project_id == "project456"


class TestAIResponse:
    """Тесты для AIResponse"""

    def test_init(self):
        """Тест инициализации"""
        response = AIResponse(
            content="Hello, world!",
            tokens_used=10,
            cost_usd=0.01,
            provider=AIProvider.OPENAI,
            model="gpt-4",
            response_time=1.5
        )
        
        assert response.content == "Hello, world!"
        assert response.tokens_used == 10
        assert response.cost_usd == 0.01
        assert response.model == "gpt-4"
        assert response.provider == AIProvider.OPENAI
        assert response.response_time == 1.5
        assert response.success is True
        assert response.error is None


class TestAIService:
    """Тесты для AIService"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.service = AIService("user123", {})

    def test_init(self):
        """Тест инициализации"""
        assert self.service.user_id == "user123"
        assert self.service.user_api_keys == {}
        assert self.service.clients == {}
        assert self.service.usage_tracker == []

    @pytest.mark.asyncio
    async def test_route_request_no_providers(self):
        """Тест маршрутизации запроса без провайдеров"""
        # Arrange
        messages = [{"role": "user", "content": "Hello"}]
        
        # Act
        response = await self.service.route_request(messages)
        
        # Assert
        assert response.success is False
        assert "No AI providers configured" in response.error

    @pytest.mark.asyncio
    async def test_route_request_with_provider(self):
        """Тест маршрутизации запроса с провайдером"""
        # Arrange
        self.service = AIService("user123", {"openai": "test_key"})
        messages = [{"role": "user", "content": "Hello"}]
        
        # Act
        response = await self.service.route_request(messages, provider="openai")
        
        # Assert
        assert response is not None

    def test_get_usage_stats_empty(self):
        """Тест получения статистики использования - пустая"""
        # Act
        stats = self.service.get_usage_stats()
        
        # Assert
        assert stats == []

    def test_get_usage_stats_with_data(self):
        """Тест получения статистики использования с данными"""
        # Arrange
        self.service.usage_tracker = [{"tokens": 100, "cost": 0.05}]
        
        # Act
        stats = self.service.get_usage_stats()
        
        # Assert
        assert len(stats) == 1
        assert stats[0]["tokens"] == 100

    def test_clear_usage_stats(self):
        """Тест очистки статистики использования"""
        # Arrange
        self.service.usage_tracker = [{"tokens": 100, "cost": 0.05}]
        
        # Act
        self.service.clear_usage_stats()
        
        # Assert
        assert self.service.usage_tracker == []