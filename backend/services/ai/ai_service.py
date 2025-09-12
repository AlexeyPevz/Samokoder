"""
AI Service
Основной сервис для работы с AI провайдерами
"""

import asyncio
import logging
from typing import Dict, List, Optional, AsyncGenerator, Any
from datetime import datetime

from .models import AIRequest, AIResponse, AIProvider
from .client_factory import AIClientFactory
from .usage_tracker import usage_tracker
from backend.patterns.circuit_breaker import circuit_breaker, CircuitBreakerConfig
from backend.core.exceptions import (
    AIServiceError, NetworkError, TimeoutError, 
    ValidationError, ConfigurationError
)
from backend.interfaces.ai import IAIService

logger = logging.getLogger(__name__)

class AIService(IAIService):
    """Основной сервис для работы с AI провайдерами"""
    
    def __init__(self):
        self._clients: Dict[AIProvider, Any] = {}
        self._fallback_order = [
            AIProvider.OPENROUTER,
            AIProvider.OPENAI,
            AIProvider.ANTHROPIC,
            AIProvider.GROQ
        ]
    
    async def initialize_clients(self, api_keys: Dict[str, str]):
        """Инициализировать клиенты с API ключами"""
        for provider in AIProvider:
            key_name = provider.value.upper() + "_API_KEY"
            if key_name in api_keys:
                try:
                    client = AIClientFactory.create_client(provider, api_keys[key_name])
                    if await client.validate_api_key():
                        self._clients[provider] = client
                        logger.info(f"Initialized {provider.value} client")
                    else:
                        logger.warning(f"Invalid API key for {provider.value}")
                except Exception as e:
                    logger.error(f"Failed to initialize {provider.value} client: {e}")
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        """Получить ответ от AI с fallback"""
        if not self._clients:
            raise ConfigurationError("No AI clients initialized")
        
        # Пробуем основной провайдер
        if request.provider in self._clients:
            try:
                response = await self._chat_with_circuit_breaker(request.provider, request)
                if response.success:
                    usage_tracker.track_request(request.user_id, response)
                    return response
            except Exception as e:
                logger.warning(f"Primary provider {request.provider} failed: {e}")
        
        # Fallback на другие провайдеры
        for provider in self._fallback_order:
            if provider != request.provider and provider in self._clients:
                try:
                    fallback_request = AIRequest(
                        messages=request.messages,
                        model=self._get_fallback_model(provider),
                        provider=provider,
                        max_tokens=request.max_tokens,
                        temperature=request.temperature,
                        user_id=request.user_id,
                        project_id=request.project_id
                    )
                    
                    response = await self._chat_with_circuit_breaker(provider, fallback_request)
                    if response.success:
                        usage_tracker.track_request(request.user_id, response)
                        return response
                except Exception as e:
                    logger.warning(f"Fallback provider {provider} failed: {e}")
        
        raise AIServiceError("All AI providers failed")
    
    async def chat_completion_stream(self, request: AIRequest) -> AsyncGenerator[AIResponse, None]:
        """Стриминг ответа от AI"""
        if not self._clients:
            raise ConfigurationError("No AI clients initialized")
        
        # Для стриминга используем только основной провайдер
        if request.provider not in self._clients:
            raise AIServiceError(f"Provider {request.provider} not available")
        
        try:
            async for response in self._stream_with_circuit_breaker(request.provider, request):
                usage_tracker.track_request(request.user_id, response)
                yield response
        except Exception as e:
            logger.error(f"Streaming failed: {e}")
            yield AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=request.provider,
                model=request.model,
                response_time=0.0,
                success=False,
                error=str(e)
            )
    
    async def _chat_with_circuit_breaker(self, provider: AIProvider, request: AIRequest) -> AIResponse:
        """Выполнить запрос с circuit breaker"""
        client = self._clients[provider]
        
        config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=AIServiceError
        )
        
        @circuit_breaker(config)
        async def _make_request():
            return await client.chat_completion(request)
        
        return await _make_request()
    
    async def _stream_with_circuit_breaker(self, provider: AIProvider, request: AIRequest) -> AsyncGenerator[AIResponse, None]:
        """Выполнить стриминг с circuit breaker"""
        client = self._clients[provider]
        
        # Упрощенная реализация стриминга
        response = await self._chat_with_circuit_breaker(provider, request)
        yield response
    
    def _get_fallback_model(self, provider: AIProvider) -> str:
        """Получить fallback модель для провайдера"""
        fallback_models = {
            AIProvider.OPENROUTER: "gpt-3.5-turbo",
            AIProvider.OPENAI: "gpt-3.5-turbo",
            AIProvider.ANTHROPIC: "claude-3-haiku-20240307",
            AIProvider.GROQ: "llama-3.1-70b-versatile"
        }
        return fallback_models.get(provider, "gpt-3.5-turbo")
    
    def get_usage_stats(self, user_id: str) -> Dict[AIProvider, Any]:
        """Получить статистику использования"""
        return usage_tracker.get_user_stats(user_id)
    
    def get_provider_stats(self, provider: AIProvider) -> Any:
        """Получить статистику по провайдеру"""
        return usage_tracker.get_provider_stats(provider)
    
    def get_available_providers(self) -> List[AIProvider]:
        """Получить список доступных провайдеров"""
        return list(self._clients.keys())

# Глобальный экземпляр сервиса
_ai_service: Optional[AIService] = None

async def get_ai_service() -> AIService:
    """Получить экземпляр AI сервиса"""
    global _ai_service
    if _ai_service is None:
        _ai_service = AIService()
    return _ai_service