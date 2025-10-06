"""
Rate limiting middleware для защиты от DoS атак.

Реализует:
- Ограничения по IP адресу
- Различные лимиты для разных эндпоинтов
- Исключения для аутентифицированных пользователей
- Настраиваемые лимиты по тарифам
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import redis.asyncio as redis
import json
import logging

from samokoder.core.config import get_config
from samokoder.core.db.models.user import User, Tier

logger = logging.getLogger(__name__)

# Глобальный rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"  # Используем Redis для распределенного лимитирования
)

class RateLimitService:
    """Сервис для управления rate limiting."""

    def __init__(self):
        self.config = get_config()
        self.redis_client = None

    async def get_redis_client(self) -> redis.Redis:
        """Получить Redis клиент."""
        if self.redis_client is None:
            self.redis_client = redis.from_url(
                self.config.redis_url,
                decode_responses=True
            )
        return self.redis_client

    def get_rate_limits(self, user: Optional[User] = None, endpoint: str = None) -> Dict[str, str]:
        """
        Получить лимиты в зависимости от пользователя и эндпоинта.

        Args:
            user: Аутентифицированный пользователь (None для анонимов)
            endpoint: Эндпоинт API

        Returns:
            Dict с лимитами для разных периодов
        """
        # Базовые лимиты
        if user and user.tier != Tier.FREE:
            # Премиум пользователи имеют более высокие лимиты
            limits = {
                "1/minute": "200",
                "1/hour": "10000",
                "1/day": "100000"
            }
        else:
            # Бесплатные пользователи и анонимы
            limits = {
                "1/minute": "30",    # 30 запросов в минуту
                "1/hour": "1000",    # 1000 запросов в час
                "1/day": "10000"     # 10000 запросов в день
            }

        # Специальные лимиты для чувствительных эндпоинтов
        sensitive_endpoints = {
            "/projects": {"1/minute": "10", "1/hour": "100"},  # Создание проектов
            "/keys": {"1/minute": "5", "1/hour": "50"},        # Управление API ключами
            "/auth": {"1/minute": "5", "1/hour": "20"},        # Аутентификация
        }

        if endpoint and endpoint in sensitive_endpoints:
            # Объединяем базовые и специальные лимиты
            limits.update(sensitive_endpoints[endpoint])

        return {f"{limit}/minute": count for limit, count in limits.items()}

    async def check_custom_limit(
        self,
        request: Request,
        user: Optional[User],
        action: str,
        limit_window: int = 60,  # секунды
        max_requests: int = 100
    ) -> bool:
        """
        Проверить кастомный лимит для специфических действий.

        Args:
            request: FastAPI Request
            user: Пользователь
            action: Действие для лимитирования
            limit_window: Окно времени в секундах
            max_requests: Максимум запросов

        Returns:
            True если лимит не превышен
        """
        client_ip = get_remote_address(request)
        user_id = user.id if user else "anonymous"

        redis_client = await self.get_redis_client()
        key = f"rate_limit:{user_id}:{client_ip}:{action}"

        # Используем Redis для атомарных операций
        pipe = redis_client.pipeline()

        # Получить текущее количество
        pipe.get(key)
        # Установить expiration если ключа нет
        pipe.set(key, 1, ex=limit_window, nx=True)
        # Инкрементировать счетчик
        pipe.incr(key)

        results = await pipe.execute()
        current_count = int(results[0]) if results[0] else 0

        if current_count > max_requests:
            logger.warning(
                f"Rate limit exceeded for {user_id}:{client_ip}:{action} "
                f"({current_count}/{max_requests})"
            )
            return False

        return True

    async def get_user_rate_limit_status(
        self,
        user: User,
        request: Request
    ) -> Dict[str, Any]:
        """
        Получить статус rate limiting для пользователя.

        Returns:
            Dict со статусом лимитов
        """
        redis_client = await self.get_redis_client()
        client_ip = get_remote_address(request)

        # Получаем статистику использования
        user_key = f"rate_limit:{user.id}:{client_ip}:*"
        keys = await redis_client.keys(user_key)

        total_requests = 0
        limits_info = {}

        for key in keys:
            count = await redis_client.get(key)
            if count:
                total_requests += int(count)

                # Парсим информацию о лимите из ключа
                action = key.split(':')[-1]
                ttl = await redis_client.ttl(key)
                limits_info[action] = {
                    'requests': int(count),
                    'ttl': ttl,
                    'resets_in': ttl if ttl > 0 else 0
                }

        return {
            'total_requests': total_requests,
            'limits': limits_info,
            'user_tier': user.tier.value,
            'timestamp': datetime.utcnow().isoformat()
        }


class RateLimitMiddleware:
    """Middleware для обработки rate limiting."""

    def __init__(self, app):
        self.app = app
        self.rate_limit_service = RateLimitService()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Создаем mock request для анализа
        request = Request(scope)

        # Пропускаем health checks и статические файлы
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            await self.app(scope, receive, send)
            return

        # Проверяем rate limits
        # Здесь будет логика проверки лимитов
        # Для простоты используем slowapi

        await self.app(scope, receive, send)


# Функция для обработки превышения лимитов
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Обработчик превышения rate limit."""
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Too many requests",
            "error_code": "RATE_LIMIT_EXCEEDED",
            "retry_after": exc.detail.split("retry after ")[-1] if "retry after" in exc.detail else "60",
            "timestamp": datetime.utcnow().isoformat()
        }
    )


# Декораторы для различных лимитов
def get_rate_limiter():
    """Получить rate limiter для dependency injection."""
    return limiter


# Специальные декораторы для разных типов запросов
def public_endpoint_limit():
    """Лимит для публичных эндпоинтов (анонимные пользователи)."""
    return limiter.limit("10/minute")


def authenticated_endpoint_limit():
    """Лимит для аутентифицированных пользователей."""
    return limiter.limit("100/minute")


def sensitive_endpoint_limit():
    """Лимит для чувствительных операций (создание проектов, управление ключами)."""
    return limiter.limit("5/minute")


def heavy_endpoint_limit():
    """Лимит для тяжелых операций (генерация кода, анализ)."""
    return limiter.limit("2/minute")
