"""
Rate Limiting Middleware для защиты от DDoS атак
"""

import time
import json
from typing import Dict, Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import logging

from backend.services.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

# Конфигурация rate limits для разных эндпоинтов
RATE_LIMITS = {
    "/api/auth/login": {"per_minute": 5, "per_hour": 50},
    "/api/auth/register": {"per_minute": 3, "per_hour": 20},
    "/api/projects": {"per_minute": 30, "per_hour": 500},
    "/api/ai/chat": {"per_minute": 20, "per_hour": 200},
    "/api/projects/*/generate": {"per_minute": 5, "per_hour": 50},
    "default": {"per_minute": 60, "per_hour": 1000}
}

async def rate_limit_middleware(request: Request, call_next):
    """
    Rate Limiting middleware для защиты от DDoS атак
    """
    try:
        # Получаем путь запроса
        path = request.url.path
        
        # Определяем rate limits для данного эндпоинта
        limits = RATE_LIMITS.get(path, RATE_LIMITS["default"])
        
        # Для динамических путей (с параметрами)
        if path.startswith("/api/projects/") and "/generate" in path:
            limits = RATE_LIMITS["/api/projects/*/generate"]
        elif path.startswith("/api/projects/") and path.count("/") == 3:
            limits = RATE_LIMITS["/api/projects"]
        
        # Получаем IP адрес клиента
        client_ip = request.client.host if request.client else "unknown"
        
        # Проверяем rate limit
        allowed, rate_info = await rate_limiter.check_rate_limit(
            user_id=client_ip,  # Используем IP как идентификатор
            endpoint=path,
            limit_per_minute=limits["per_minute"],
            limit_per_hour=limits["per_hour"]
        )
        
        if not allowed:
            logger.warning(
                "rate_limit_exceeded",
                client_ip=client_ip,
                path=path,
                minute_requests=rate_info["minute_requests"],
                hour_requests=rate_info["hour_requests"]
            )
            
            retry_after = 60 if not rate_info["minute_allowed"] else 3600
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Слишком много запросов. Попробуйте позже.",
                    "retry_after": retry_after,
                    "limits": {
                        "per_minute": limits["per_minute"],
                        "per_hour": limits["per_hour"]
                    },
                    "current_usage": {
                        "minute_requests": rate_info["minute_requests"],
                        "hour_requests": rate_info["hour_requests"]
                    }
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit-Minute": str(limits["per_minute"]),
                    "X-RateLimit-Limit-Hour": str(limits["per_hour"]),
                    "X-RateLimit-Remaining-Minute": str(max(0, limits["per_minute"] - rate_info["minute_requests"])),
                    "X-RateLimit-Remaining-Hour": str(max(0, limits["per_hour"] - rate_info["hour_requests"]))
                }
            )
        
        # Добавляем информацию о rate limit в заголовки ответа
        response = await call_next(request)
        
        response.headers["X-RateLimit-Limit-Minute"] = str(limits["per_minute"])
        response.headers["X-RateLimit-Limit-Hour"] = str(limits["per_hour"])
        response.headers["X-RateLimit-Remaining-Minute"] = str(max(0, limits["per_minute"] - rate_info["minute_requests"]))
        response.headers["X-RateLimit-Remaining-Hour"] = str(max(0, limits["per_hour"] - rate_info["hour_requests"]))
        
        return response
        
    except Exception as e:
        logger.error("rate_limit_middleware_error", error=str(e), error_type=type(e).__name__)
        # В случае ошибки в rate limiting, пропускаем запрос
        return await call_next(request)