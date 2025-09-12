"""
AI Client Factory
Фабрика для создания AI клиентов
"""

from typing import Dict, Optional
import logging

from .base_client import AIProviderClient
from .models import AIProvider
from .openrouter_client import OpenRouterClient
from .openai_client import OpenAIClient
from .anthropic_client import AnthropicClient
from .groq_client import GroqClient

logger = logging.getLogger(__name__)

class AIClientFactory:
    """Фабрика для создания AI клиентов"""
    
    _clients: Dict[AIProvider, type] = {
        AIProvider.OPENROUTER: OpenRouterClient,
        AIProvider.OPENAI: OpenAIClient,
        AIProvider.ANTHROPIC: AnthropicClient,
        AIProvider.GROQ: GroqClient,
    }
    
    @classmethod
    def create_client(cls, provider: AIProvider, api_key: str) -> AIProviderClient:
        """Создать клиент для указанного провайдера"""
        if provider not in cls._clients:
            raise ValueError(f"Unsupported AI provider: {provider}")
        
        client_class = cls._clients[provider]
        return client_class(api_key)
    
    @classmethod
    def get_available_providers(cls) -> list[AIProvider]:
        """Получить список доступных провайдеров"""
        return list(cls._clients.keys())
    
    @classmethod
    def register_client(cls, provider: AIProvider, client_class: type):
        """Зарегистрировать новый клиент"""
        cls._clients[provider] = client_class
        logger.info(f"Registered AI client for provider: {provider}")