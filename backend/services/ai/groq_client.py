"""
Groq Client
Клиент для работы с Groq API
"""

import logging
from datetime import datetime
from typing import Optional
import httpx

from .base_client import AIProviderClient
from .models import AIRequest, AIResponse, AIProvider

logger = logging.getLogger(__name__)

class GroqClient(AIProviderClient):
    """Клиент для Groq"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.GROQ)
        self.api_key = api_key
        self.base_url = "https://api.groq.com/openai/v1"
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        start_time = datetime.now()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": request.model,
                        "messages": request.messages,
                        "max_tokens": request.max_tokens,
                        "temperature": request.temperature
                    }
                )
                
                response.raise_for_status()
                data = response.json()
                
                response_time = (datetime.now() - start_time).total_seconds()
                
                return AIResponse(
                    content=data["choices"][0]["message"]["content"],
                    tokens_used=data["usage"]["total_tokens"],
                    cost_usd=0.0,  # Groq бесплатный
                    provider=self.provider,
                    model=request.model,
                    response_time=response_time,
                    success=True
                )
                
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Groq API error: {e}")
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
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "llama-3.1-70b-versatile",
                        "messages": [{"role": "user", "content": "test"}],
                        "max_tokens": 1
                    }
                )
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Groq API key validation failed: {e}")
            return False