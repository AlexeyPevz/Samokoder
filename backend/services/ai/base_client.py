"""
AI Base Client
Базовый класс для AI провайдеров
"""

from abc import ABC, abstractmethod
from typing import Optional
from .models import AIRequest, AIResponse, AIProvider

class AIProviderClient(ABC):
    """Базовый класс для AI провайдеров"""
    
    def __init__(self, api_key: str, provider: AIProvider):
        self.api_key = api_key
        self.provider = provider
        self.client = None
    
    @abstractmethod
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        """Основной метод для получения ответа от AI"""
        pass
    
    @abstractmethod
    async def validate_api_key(self) -> bool:
        """Проверка валидности API ключа"""
        pass