"""
Интерфейсы для AI сервисов
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum

class AIProvider(Enum):
    """Провайдеры AI"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    OPENROUTER = "openrouter"

class IAIProviderClient(ABC):
    """Интерфейс AI провайдера"""
    
    @abstractmethod
    async def generate_response(self, prompt: str, **kwargs) -> str:
        """Сгенерировать ответ"""
        pass
    
    @abstractmethod
    async def generate_stream(self, prompt: str, **kwargs):
        """Сгенерировать потоковый ответ"""
        pass
    
    @abstractmethod
    def get_provider(self) -> AIProvider:
        """Получить провайдера"""
        pass
    
    @abstractmethod
    def get_usage_stats(self) -> Dict[str, Any]:
        """Получить статистику использования"""
        pass

class IAIService(ABC):
    """Интерфейс AI сервиса"""
    
    @abstractmethod
    async def generate_response(self, prompt: str, provider: Optional[AIProvider] = None, **kwargs) -> str:
        """Сгенерировать ответ"""
        pass
    
    @abstractmethod
    async def generate_stream(self, prompt: str, provider: Optional[AIProvider] = None, **kwargs):
        """Сгенерировать потоковый ответ"""
        pass
    
    @abstractmethod
    def get_available_providers(self) -> List[AIProvider]:
        """Получить доступные провайдеры"""
        pass
    
    @abstractmethod
    def get_usage_statistics(self) -> Dict[str, Any]:
        """Получить статистику использования"""
        pass
    
    @abstractmethod
    def set_default_provider(self, provider: AIProvider):
        """Установить провайдера по умолчанию"""
        pass