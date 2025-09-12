"""
Anthropic Client
Клиент для работы с Anthropic API
"""

import logging
from datetime import datetime
from typing import Optional

from anthropic import AsyncAnthropic

from .base_client import AIProviderClient
from .models import AIRequest, AIResponse, AIProvider

logger = logging.getLogger(__name__)

class AnthropicClient(AIProviderClient):
    """Клиент для Anthropic"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.ANTHROPIC)
        self.client = AsyncAnthropic(api_key=api_key)
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        start_time = datetime.now()
        
        try:
            # Конвертируем сообщения в формат Anthropic
            messages = []
            system_message = ""
            
            for msg in request.messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    messages.append({
                        "role": msg["role"],
                        "content": msg["content"]
                    })
            
            response = await self.client.messages.create(
                model=request.model,
                messages=messages,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                system=system_message if system_message else None
            )
            
            response_time = (datetime.now() - start_time).total_seconds()
            
            return AIResponse(
                content=response.content[0].text,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
                cost_usd=self._calculate_cost(
                    response.usage.input_tokens + response.usage.output_tokens, 
                    request.model
                ),
                provider=self.provider,
                model=request.model,
                response_time=response_time,
                success=True
            )
            
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Anthropic API error: {e}")
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
            response = await self.client.messages.create(
                model="claude-3-haiku-20240307",
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1
            )
            return True
        except Exception as e:
            logger.warning(f"Anthropic API key validation failed: {e}")
            return False
    
    def _calculate_cost(self, tokens: int, model: str) -> float:
        """Расчет стоимости запроса"""
        cost_per_1k_tokens = {
            "claude-3-opus-20240229": 0.015,
            "claude-3-sonnet-20240229": 0.003,
            "claude-3-haiku-20240307": 0.00025,
        }
        
        base_cost = cost_per_1k_tokens.get(model, 0.003)
        return (tokens / 1000) * base_cost