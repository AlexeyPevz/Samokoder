"""
OpenAI Client
Клиент для работы с OpenAI API
"""

import logging
from datetime import datetime
from typing import Optional

from openai import AsyncOpenAI

from .base_client import AIProviderClient
from .models import AIRequest, AIResponse, AIProvider

logger = logging.getLogger(__name__)

class OpenAIClient(AIProviderClient):
    """Клиент для OpenAI"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.OPENAI)
        self.client = AsyncOpenAI(api_key=api_key)
    
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
            logger.error(f"OpenAI API error: {e}")
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
            response = await self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1
            )
            return True
        except Exception as e:
            logger.warning(f"OpenAI API key validation failed: {e}")
            return False
    
    def _calculate_cost(self, tokens: int, model: str) -> float:
        """Расчет стоимости запроса"""
        cost_per_1k_tokens = {
            "gpt-4": 0.03,
            "gpt-4-turbo": 0.01,
            "gpt-3.5-turbo": 0.002,
            "gpt-3.5-turbo-16k": 0.004,
        }
        
        base_cost = cost_per_1k_tokens.get(model, 0.002)
        return (tokens / 1000) * base_cost