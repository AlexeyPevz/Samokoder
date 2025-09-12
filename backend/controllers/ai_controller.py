"""
AI Controller
Контроллер для управления AI сервисами
"""

import logging
from typing import Dict, List, Optional, Any, AsyncGenerator

from backend.services.ai.ai_service import get_ai_service, AIRequest, AIResponse, AIProvider
from backend.services.ai.usage_tracker import usage_tracker

logger = logging.getLogger(__name__)

class AIController:
    """Контроллер для управления AI сервисами"""
    
    def __init__(self):
        self.ai_service = None
    
    async def initialize(self, api_keys: Dict[str, str]):
        """Инициализировать AI сервис с API ключами"""
        self.ai_service = await get_ai_service()
        await self.ai_service.initialize_clients(api_keys)
        logger.info("AI Controller initialized")
    
    async def chat_completion(self, messages: List[Dict[str, str]], model: str, 
                            provider: AIProvider, user_id: str, project_id: str = "",
                            max_tokens: int = 4096, temperature: float = 0.7) -> AIResponse:
        """Выполнить чат-запрос к AI"""
        if not self.ai_service:
            raise Exception("AI Controller not initialized")
        
        request = AIRequest(
            messages=messages,
            model=model,
            provider=provider,
            max_tokens=max_tokens,
            temperature=temperature,
            user_id=user_id,
            project_id=project_id
        )
        
        return await self.ai_service.chat_completion(request)
    
    async def chat_completion_stream(self, messages: List[Dict[str, str]], model: str,
                                   provider: AIProvider, user_id: str, project_id: str = "",
                                   max_tokens: int = 4096, temperature: float = 0.7) -> AsyncGenerator[AIResponse, None]:
        """Выполнить стриминг чат-запроса к AI"""
        if not self.ai_service:
            raise Exception("AI Controller not initialized")
        
        request = AIRequest(
            messages=messages,
            model=model,
            provider=provider,
            max_tokens=max_tokens,
            temperature=temperature,
            user_id=user_id,
            project_id=project_id
        )
        
        async for response in self.ai_service.chat_completion_stream(request):
            yield response
    
    def get_usage_stats(self, user_id: str) -> Dict[AIProvider, Any]:
        """Получить статистику использования AI для пользователя"""
        if not self.ai_service:
            return {}
        
        return self.ai_service.get_usage_stats(user_id)
    
    def get_provider_stats(self, provider: AIProvider) -> Any:
        """Получить статистику по провайдеру"""
        if not self.ai_service:
            return None
        
        return self.ai_service.get_provider_stats(provider)
    
    def get_available_providers(self) -> List[AIProvider]:
        """Получить список доступных провайдеров"""
        if not self.ai_service:
            return []
        
        return self.ai_service.get_available_providers()
    
    def get_global_usage_stats(self) -> Dict[str, Any]:
        """Получить глобальную статистику использования"""
        return {
            "total_requests": len(usage_tracker._requests),
            "recent_requests_24h": len(usage_tracker.get_recent_requests(24)),
            "providers": {
                provider.value: usage_tracker.get_provider_stats(provider).__dict__
                for provider in AIProvider
            }
        }

def get_ai_controller() -> AIController:
    """Получить контроллер AI (использует DI контейнер)"""
    from backend.core.dependency_injection import get_container
    container = get_container()
    return container.get(AIController)