"""
OpenRouter AI Client
Клиент для работы с OpenRouter API
"""

import logging
from datetime import datetime
from typing import Optional

from openai import AsyncOpenAI

from .base_client import AIProviderClient
from .models import AIRequest, AIResponse, AIProvider

logger = logging.getLogger(__name__)

class OpenRouterClient(AIProviderClient):
    """Клиент для OpenRouter"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.OPENROUTER)
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1"
        )
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        start_time = datetime.now()
        
        try:
            response = await self.client.chat.completions.create(
                model=request.model,
                messages=request.messages,
                max_tokens=request.max_tokens,
                temperature=request.temperature
            )
            
            response_time = (datetime.now() - start_time).total_seconds()
            
            return AIResponse(
                content=response.choices[0].message.content,
                tokens_used=response.usage.total_tokens,
                cost_usd=self._calculate_cost(response.usage.total_tokens, request.model),
                provider=self.provider,
                model=request.model,
                response_time=response_time,
                success=True
            )
            
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"OpenRouter API error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=response_time,
                success=False,
                error=str(e)
            )
    
    async def validate_api_key(self) -> bool:
        """Проверка валидности API ключа"""
        try:
            # Простой запрос для проверки ключа
            response = await self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1
            )
            return True
        except Exception as e:
            logger.warning(f"OpenRouter API key validation failed: {e}")
            return False
    
    def _calculate_cost(self, tokens: int, model: str) -> float:
        """Расчет стоимости запроса"""
        # Упрощенная модель ценообразования OpenRouter
        cost_per_1k_tokens = {
            "gpt-4": 0.03,
            "gpt-3.5-turbo": 0.002,
            "claude-3-opus": 0.015,
            "claude-3-sonnet": 0.003,
            "claude-3-haiku": 0.00025,
        }
        
        base_cost = cost_per_1k_tokens.get(model, 0.002)
        return (tokens / 1000) * base_cost