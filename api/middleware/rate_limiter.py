"""Rate limiting middleware using SlowAPI."""
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from typing import Optional
import os
from samokoder.core.config import get_config


def _get_identifier(request):
    """Получить идентификатор клиента для rate limiting.
    
    Приоритет:
    1. User ID из JWT токена (если аутентифицирован)
    2. IP адрес клиента
    
    Args:
        request: FastAPI request object
    
    Returns:
        Строка-идентификатор клиента
    """
    # Проверяем наличие user в state (установлено middleware аутентификации)
    if hasattr(request.state, "user") and request.state.user:
        user_id = getattr(request.state.user, "id", None)
        if user_id:
            return f"user:{user_id}"
    
    # Fallback на IP адрес
    return f"ip:{get_remote_address(request)}"


# Создаём limiter с Redis storage из конфигурации
_redis_url = os.getenv("REDIS_URL") or get_config().redis_url
limiter = Limiter(
    key_func=_get_identifier,
    storage_uri=_redis_url,
    default_limits=["100/minute"],  # По умолчанию для аутентифицированных
    headers_enabled=True,  # Добавляет X-RateLimit-* заголовки
)


# Лимиты для разных типов endpoints
LIMITS = {
    # Публичные endpoints (без авторизации)
    "public": "10/minute",
    
    # Аутентифицированные endpoints
    "authenticated": "100/minute",
    
    # Создание проектов (ресурсоёмкие операции)
    "project_create": "10/day",
    
    # LLM запросы (очень дорогие)
    "llm_generate": "50/hour",
    
    # Login/Register endpoints (защита от брутфорса)
    "auth": "5/minute",
}


def get_rate_limit(limit_type: str = "authenticated") -> str:
    """Получить rate limit для определённого типа endpoint.
    
    Args:
        limit_type: Тип лимита из LIMITS
    
    Returns:
        Строка лимита в формате SlowAPI (например, "100/minute")
    """
    return LIMITS.get(limit_type, LIMITS["authenticated"])
