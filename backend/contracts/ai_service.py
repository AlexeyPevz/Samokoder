"""
AI Service contracts
"""
from typing import Protocol, Dict, Any, AsyncGenerator, Optional
from backend.models.requests import ChatRequest

class AIServiceProtocol(Protocol):
    """Protocol for AI service implementations"""
    
    async def chat_completion(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Perform chat completion"""
        ...
    
    async def chat_completion_stream(self, request: Dict[str, Any]) -> AsyncGenerator[Dict[str, Any], None]:
        """Perform streaming chat completion"""
        ...
    
    async def validate_api_key(self, provider: str, api_key: str) -> bool:
        """Validate API key for provider"""
        ...
    
    async def get_usage_stats(self, provider: str) -> Dict[str, Any]:
        """Get usage statistics for provider"""
        ...
    
    async def get_available_models(self, provider: str) -> list[str]:
        """Get available models for provider"""
        ...
    
    async def estimate_cost(self, request: Dict[str, Any]) -> float:
        """Estimate cost for request"""
        ...

class AIProviderProtocol(Protocol):
    """Protocol for individual AI provider implementations"""
    
    async def chat_completion(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Perform chat completion with this provider"""
        ...
    
    async def chat_completion_stream(self, request: Dict[str, Any]) -> AsyncGenerator[Dict[str, Any], None]:
        """Perform streaming chat completion with this provider"""
        ...
    
    async def validate_api_key(self, api_key: str) -> bool:
        """Validate API key for this provider"""
        ...
    
    async def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics for this provider"""
        ...
    
    async def get_available_models(self) -> list[str]:
        """Get available models for this provider"""
        ...
    
    async def estimate_cost(self, request: Dict[str, Any]) -> float:
        """Estimate cost for request with this provider"""
        ...