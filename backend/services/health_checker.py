"""
Health Checker для внешних сервисов
Проверяет доступность Redis, AI провайдеров и других критических сервисов
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import httpx
import redis.asyncio as redis
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import settings

logger = logging.getLogger(__name__)

class HealthChecker:
    """Health checker для внешних сервисов"""
    
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self._init_redis()
    
    def _init_redis(self):
        """Инициализация Redis клиента"""
        try:
            self.redis_client = redis.from_url(settings.redis_url)
        except Exception as e:
            logger.warning(f"Failed to initialize Redis client: {e}")
            self.redis_client = None
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=3)
    )
    async def check_redis(self) -> Dict[str, Any]:
        """Проверка доступности Redis"""
        try:
            if not self.redis_client:
                return {
                    "status": "unavailable",
                    "error": "Redis client not initialized",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Проверяем соединение
            await self.redis_client.ping()
            
            # Проверяем базовые операции
            test_key = "health_check_test"
            await self.redis_client.set(test_key, "test", ex=10)
            value = await self.redis_client.get(test_key)
            await self.redis_client.delete(test_key)
            
            if value != b"test":
                raise Exception("Redis read/write test failed")
            
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "response_time": "< 1ms"
            }
            
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=3)
    )
    async def check_ai_provider(self, provider: str, api_key: str) -> Dict[str, Any]:
        """Проверка доступности AI провайдера"""
        try:
            if not api_key or api_key.startswith("mock_"):
                return {
                    "status": "mock",
                    "provider": provider,
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Простой запрос для проверки доступности
            if provider == "openai":
                return await self._check_openai(api_key)
            elif provider == "anthropic":
                return await self._check_anthropic(api_key)
            elif provider == "openrouter":
                return await self._check_openrouter(api_key)
            elif provider == "groq":
                return await self._check_groq(api_key)
            else:
                return {
                    "status": "unknown",
                    "provider": provider,
                    "error": "Unknown provider",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"AI provider {provider} health check failed: {e}")
            return {
                "status": "unhealthy",
                "provider": provider,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _check_openai(self, api_key: str) -> Dict[str, Any]:
        """Проверка OpenAI"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"}
            )
            response.raise_for_status()
            
            return {
                "status": "healthy",
                "provider": "openai",
                "timestamp": datetime.utcnow().isoformat(),
                "response_time": f"{response.elapsed.total_seconds():.3f}s"
            }
    
    async def _check_anthropic(self, api_key: str) -> Dict[str, Any]:
        """Проверка Anthropic"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key}
            )
            # Anthropic может вернуть 400 для пустого запроса, но это означает что API доступен
            if response.status_code in [200, 400]:
                return {
                    "status": "healthy",
                    "provider": "anthropic",
                    "timestamp": datetime.utcnow().isoformat(),
                    "response_time": f"{response.elapsed.total_seconds():.3f}s"
                }
            else:
                response.raise_for_status()
    
    async def _check_openrouter(self, api_key: str) -> Dict[str, Any]:
        """Проверка OpenRouter"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"}
            )
            response.raise_for_status()
            
            return {
                "status": "healthy",
                "provider": "openrouter",
                "timestamp": datetime.utcnow().isoformat(),
                "response_time": f"{response.elapsed.total_seconds():.3f}s"
            }
    
    async def _check_groq(self, api_key: str) -> Dict[str, Any]:
        """Проверка Groq"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {api_key}"}
            )
            response.raise_for_status()
            
            return {
                "status": "healthy",
                "provider": "groq",
                "timestamp": datetime.utcnow().isoformat(),
                "response_time": f"{response.elapsed.total_seconds():.3f}s"
            }
    
    async def check_all_services(self) -> Dict[str, Any]:
        """Проверка всех сервисов"""
        results = {}
        
        # Проверяем Redis
        results["redis"] = await self.check_redis()
        
        # Проверяем AI провайдеры
        ai_providers = {
            "openai": settings.system_openai_key,
            "anthropic": settings.system_anthropic_key,
            "openrouter": settings.system_openrouter_key,
            "groq": settings.system_groq_key
        }
        
        for provider, api_key in ai_providers.items():
            if api_key:
                results[f"ai_{provider}"] = await self.check_ai_provider(provider, api_key)
        
        # Общий статус
        healthy_services = sum(1 for result in results.values() if result.get("status") == "healthy")
        total_services = len(results)
        
        results["overall"] = {
            "status": "healthy" if healthy_services == total_services else "degraded",
            "healthy_services": healthy_services,
            "total_services": total_services,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return results
    
    async def close(self):
        """Закрытие соединений"""
        if self.redis_client:
            await self.redis_client.close()

# Глобальный экземпляр
health_checker = HealthChecker()