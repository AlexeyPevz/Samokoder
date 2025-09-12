"""
Адаптер для AI сервисов
Уменьшает связность между компонентами
"""

import logging
from typing import Dict, Any, List, Optional, AsyncGenerator
from backend.interfaces.ai import IAIService, AIProvider

logger = logging.getLogger(__name__)

class AIAdapter:
    """Адаптер для AI сервисов"""
    
    def __init__(self, ai_service: IAIService):
        self.ai_service = ai_service
    
    async def generate_response(self, prompt: str, provider: Optional[AIProvider] = None, **kwargs) -> str:
        """Сгенерировать ответ"""
        return await self.ai_service.generate_response(prompt, provider, **kwargs)
    
    async def generate_stream(self, prompt: str, provider: Optional[AIProvider] = None, **kwargs) -> AsyncGenerator[str, None]:
        """Сгенерировать потоковый ответ"""
        async for chunk in self.ai_service.generate_stream(prompt, provider, **kwargs):
            yield chunk
    
    def get_available_providers(self) -> List[AIProvider]:
        """Получить доступные провайдеры"""
        return self.ai_service.get_available_providers()
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """Получить статистику использования"""
        return self.ai_service.get_usage_statistics()
    
    def set_default_provider(self, provider: AIProvider):
        """Установить провайдера по умолчанию"""
        self.ai_service.set_default_provider(provider)
    
    def get_provider_stats(self, provider: AIProvider) -> Dict[str, Any]:
        """Получить статистику провайдера"""
        stats = self.get_usage_statistics()
        return stats.get("providers", {}).get(provider.value, {})
    
    def is_provider_available(self, provider: AIProvider) -> bool:
        """Проверить доступность провайдера"""
        available_providers = self.get_available_providers()
        return provider in available_providers
    
    def get_total_usage(self) -> Dict[str, Any]:
        """Получить общую статистику использования"""
        stats = self.get_usage_statistics()
        return {
            "total_requests": stats.get("total_requests", 0),
            "total_tokens": stats.get("total_tokens", 0),
            "total_cost": stats.get("total_cost", 0.0),
            "average_response_time": stats.get("average_response_time", 0.0),
            "error_rate": stats.get("error_rate", 0.0)
        }