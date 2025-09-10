"""
Rate Limiting Middleware для FastAPI
Автоматически применяет rate limiting ко всем эндпоинтам
"""

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Callable
import logging
from datetime import datetime

from backend.services.rate_limiter import rate_limiter
from config.settings import settings

logger = logging.getLogger(__name__)

class RateLimitMiddleware:
    """Middleware для автоматического rate limiting"""
    
    def __init__(self, app):
        self.app = app
        # Настройки rate limiting по умолчанию
        self.default_limits = {
            "minute": settings.rate_limit_per_minute,
            "hour": settings.rate_limit_per_hour
        }
        
        # Специальные лимиты для разных эндпоинтов
        self.endpoint_limits = {
            "/api/auth/login": {"minute": 5, "hour": 50},
            "/api/auth/register": {"minute": 3, "hour": 20},
            "/api/projects": {"minute": 10, "hour": 100},
            "/api/ai/chat": {"minute": 30, "hour": 500},
            "/api/ai/usage": {"minute": 20, "hour": 200},
        }
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Получаем пользователя (если аутентифицирован)
        user_id = await self._get_user_id(request)
        
        # Получаем лимиты для эндпоинта
        endpoint = request.url.path
        limits = self.endpoint_limits.get(endpoint, self.default_limits)
        
        # Проверяем rate limit
        if user_id:
            allowed, rate_info = await rate_limiter.check_rate_limit(
                user_id=user_id,
                endpoint=endpoint,
                limit_per_minute=limits["minute"],
                limit_per_hour=limits["hour"]
            )
            
            if not allowed:
                logger.warning(f"Rate limit exceeded for user {user_id} on {endpoint}")
                
                response = JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "rate_limit_exceeded",
                        "message": "Превышен лимит запросов",
                        "details": {
                            "minute_requests": rate_info.minute_requests,
                            "hour_requests": rate_info.hour_requests,
                            "minute_limit": rate_info.minute_limit,
                            "hour_limit": rate_info.hour_limit,
                            "retry_after": 60 if not rate_info.minute_allowed else 3600
                        }
                    },
                    headers={
                        "Retry-After": str(60 if not rate_info.minute_allowed else 3600),
                        "X-RateLimit-Limit-Minute": str(rate_info.minute_limit),
                        "X-RateLimit-Limit-Hour": str(rate_info.hour_limit),
                        "X-RateLimit-Remaining-Minute": str(max(0, rate_info.minute_limit - rate_info.minute_requests)),
                        "X-RateLimit-Remaining-Hour": str(max(0, rate_info.hour_limit - rate_info.hour_requests))
                    }
                )
                
                await response(scope, receive, send)
                return
        
        await self.app(scope, receive, send)
    
    async def _get_user_id(self, request: Request) -> str:
        """Получает ID пользователя из запроса"""
        try:
            # Пытаемся получить токен из заголовка Authorization
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return "anonymous"
            
            token = auth_header.split(" ")[1]
            
            # Для mock токенов
            if token.startswith("mock_token_"):
                return f"mock_user_{token.replace('mock_token_', '')}"
            
            # Для реальных токенов можно добавить декодирование JWT
            # Пока возвращаем хеш токена как user_id
            return f"user_{hash(token) % 1000000}"
            
        except Exception as e:
            logger.debug(f"Error getting user ID: {e}")
            return "anonymous"

def create_rate_limit_decorator(
    requests_per_minute: int = 60,
    requests_per_hour: int = 1000
):
    """Создает декоратор для rate limiting конкретного эндпоинта"""
    
    async def rate_limit_dependency(request: Request):
        user_id = await _get_user_id_from_request(request)
        
        allowed, rate_info = await rate_limiter.check_rate_limit(
            user_id=user_id,
            endpoint=request.url.path,
            limit_per_minute=requests_per_minute,
            limit_per_hour=requests_per_hour
        )
        
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": "Превышен лимит запросов",
                    "minute_requests": rate_info.minute_requests,
                    "hour_requests": rate_info.hour_requests,
                    "minute_limit": rate_info.minute_limit,
                    "hour_limit": rate_info.hour_limit,
                    "retry_after": 60 if not rate_info.minute_allowed else 3600
                },
                headers={
                    "Retry-After": str(60 if not rate_info.minute_allowed else 3600),
                    "X-RateLimit-Limit-Minute": str(rate_info.minute_limit),
                    "X-RateLimit-Limit-Hour": str(rate_info.hour_limit),
                    "X-RateLimit-Remaining-Minute": str(max(0, rate_info.minute_limit - rate_info.minute_requests)),
                    "X-RateLimit-Remaining-Hour": str(max(0, rate_info.hour_limit - rate_info.hour_requests))
                }
            )
        
        return rate_info
    
    return rate_limit_dependency

async def _get_user_id_from_request(request: Request) -> str:
    """Получает ID пользователя из запроса"""
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return "anonymous"
        
        token = auth_header.split(" ")[1]
        
        if token.startswith("mock_token_"):
            return f"mock_user_{token.replace('mock_token_', '')}"
        
        return f"user_{hash(token) % 1000000}"
        
    except Exception:
        return "anonymous"

# Предустановленные декораторы для разных типов эндпоинтов
auth_rate_limit = create_rate_limit_decorator(requests_per_minute=5, requests_per_hour=50)
api_rate_limit = create_rate_limit_decorator(requests_per_minute=60, requests_per_hour=1000)
ai_rate_limit = create_rate_limit_decorator(requests_per_minute=30, requests_per_hour=500)
strict_rate_limit = create_rate_limit_decorator(requests_per_minute=10, requests_per_hour=100)