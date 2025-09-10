"""
AI Service Implementation
"""
import logging
from typing import Dict, Any, AsyncGenerator
from backend.contracts.ai_service import AIServiceProtocol
from backend.services.ai_service import get_ai_service

logger = logging.getLogger(__name__)

class AIServiceImpl(AIServiceProtocol):
    """Implementation of AI Service Protocol"""
    
    def __init__(self):
        self._ai_service = None
    
    def _get_ai_service(self):
        """Get AI service instance"""
        if self._ai_service is None:
            self._ai_service = get_ai_service()
        return self._ai_service
    
    async def chat_completion(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Perform chat completion"""
        try:
            ai_service = self._get_ai_service()
            return await ai_service.chat_completion(request)
        except Exception as e:
            logger.error(f"AI chat completion failed: {e}")
            raise
    
    async def chat_completion_stream(self, request: Dict[str, Any]) -> AsyncGenerator[Dict[str, Any], None]:
        """Perform streaming chat completion"""
        try:
            ai_service = self._get_ai_service()
            async for chunk in ai_service.chat_completion_stream(request):
                yield chunk
        except Exception as e:
            logger.error(f"AI stream chat completion failed: {e}")
            raise
    
    async def validate_api_key(self, provider: str, api_key: str) -> bool:
        """Validate API key for provider"""
        try:
            ai_service = self._get_ai_service()
            return await ai_service.validate_api_key(provider, api_key)
        except Exception as e:
            logger.error(f"API key validation failed for {provider}: {e}")
            return False
    
    async def get_usage_stats(self, provider: str) -> Dict[str, Any]:
        """Get usage statistics for provider"""
        try:
            ai_service = self._get_ai_service()
            return await ai_service.get_usage_stats(provider)
        except Exception as e:
            logger.error(f"Failed to get usage stats for {provider}: {e}")
            return {}
    
    async def get_available_models(self, provider: str) -> list[str]:
        """Get available models for provider"""
        try:
            ai_service = self._get_ai_service()
            return await ai_service.get_available_models(provider)
        except Exception as e:
            logger.error(f"Failed to get models for {provider}: {e}")
            return []
    
    async def estimate_cost(self, request: Dict[str, Any]) -> float:
        """Estimate cost for request"""
        try:
            ai_service = self._get_ai_service()
            return await ai_service.estimate_cost(request)
        except Exception as e:
            logger.error(f"Failed to estimate cost: {e}")
            return 0.0