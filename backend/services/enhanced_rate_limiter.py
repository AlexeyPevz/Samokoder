"""
Улучшенный rate limiter с поддержкой различных стратегий
"""

import time
import structlog
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import asyncio
from collections import defaultdict, deque

logger = structlog.get_logger(__name__)

class RateLimitStrategy(Enum):
    """Стратегии rate limiting"""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"

@dataclass
class RateLimitConfig:
    """Конфигурация rate limiting"""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_limit: int = 100
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    window_size_seconds: int = 60
    cleanup_interval_seconds: int = 300  # 5 минут

@dataclass
class RateLimitResult:
    """Результат проверки rate limit"""
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[float] = None
    limit: int = 0
    window_size: int = 0

class EnhancedRateLimiter:
    """Улучшенный rate limiter с поддержкой различных стратегий"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.tokens: Dict[str, float] = defaultdict(lambda: config.burst_limit)
        self.last_update: Dict[str, float] = defaultdict(time.time)
        self.lock = asyncio.Lock()
        
        # Запускаем задачу очистки
        asyncio.create_task(self._cleanup_old_entries())
    
    async def is_allowed(
        self, 
        identifier: str, 
        endpoint: str = None,
        custom_limit: Optional[int] = None
    ) -> RateLimitResult:
        """
        Проверить, разрешен ли запрос.
        
        Args:
            identifier: Идентификатор пользователя/IP
            endpoint: Эндпоинт (для специфичных лимитов)
            custom_limit: Кастомный лимит для эндпоинта
            
        Returns:
            RateLimitResult: Результат проверки
        """
        async with self.lock:
            key = f"{identifier}:{endpoint}" if endpoint else identifier
            limit = custom_limit or self._get_limit_for_endpoint(endpoint)
            
            if self.config.strategy == RateLimitStrategy.FIXED_WINDOW:
                return await self._check_fixed_window(key, limit)
            elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
                return await self._check_sliding_window(key, limit)
            elif self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
                return await self._check_token_bucket(key, limit)
            elif self.config.strategy == RateLimitStrategy.LEAKY_BUCKET:
                return await self._check_leaky_bucket(key, limit)
            else:
                return await self._check_sliding_window(key, limit)
    
    def _get_limit_for_endpoint(self, endpoint: str) -> int:
        """Получить лимит для конкретного эндпоинта"""
        if not endpoint:
            return self.config.requests_per_minute
        
        # Специфичные лимиты для эндпоинтов
        endpoint_limits = {
            "/api/auth/login": 5,
            "/api/auth/register": 3,
            "/api/ai/chat": 30,
            "/api/projects": 10,
            "/api/health": 100,
        }
        
        return endpoint_limits.get(endpoint, self.config.requests_per_minute)
    
    async def _check_fixed_window(self, key: str, limit: int) -> RateLimitResult:
        """Проверка с фиксированным окном"""
        now = time.time()
        window_start = now - (now % self.config.window_size_seconds)
        
        # Очищаем старые записи
        requests = self.requests[key]
        while requests and requests[0] < window_start:
            requests.popleft()
        
        # Проверяем лимит
        if len(requests) >= limit:
            reset_time = window_start + self.config.window_size_seconds
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                retry_after=reset_time - now,
                limit=limit,
                window_size=self.config.window_size_seconds
            )
        
        # Добавляем запрос
        requests.append(now)
        
        return RateLimitResult(
            allowed=True,
            remaining=limit - len(requests),
            reset_time=window_start + self.config.window_size_seconds,
            limit=limit,
            window_size=self.config.window_size_seconds
        )
    
    async def _check_sliding_window(self, key: str, limit: int) -> RateLimitResult:
        """Проверка со скользящим окном"""
        now = time.time()
        window_start = now - self.config.window_size_seconds
        
        # Очищаем старые записи
        requests = self.requests[key]
        while requests and requests[0] < window_start:
            requests.popleft()
        
        # Проверяем лимит
        if len(requests) >= limit:
            oldest_request = requests[0] if requests else now
            reset_time = oldest_request + self.config.window_size_seconds
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                retry_after=reset_time - now,
                limit=limit,
                window_size=self.config.window_size_seconds
            )
        
        # Добавляем запрос
        requests.append(now)
        
        return RateLimitResult(
            allowed=True,
            remaining=limit - len(requests),
            reset_time=now + self.config.window_size_seconds,
            limit=limit,
            window_size=self.config.window_size_seconds
        )
    
    async def _check_token_bucket(self, key: str, limit: int) -> RateLimitResult:
        """Проверка с токен bucket"""
        now = time.time()
        time_passed = now - self.last_update[key]
        
        # Добавляем токены за прошедшее время
        tokens_to_add = time_passed * (limit / self.config.window_size_seconds)
        self.tokens[key] = min(
            self.config.burst_limit,
            self.tokens[key] + tokens_to_add
        )
        self.last_update[key] = now
        
        # Проверяем наличие токенов
        if self.tokens[key] >= 1:
            self.tokens[key] -= 1
            return RateLimitResult(
                allowed=True,
                remaining=int(self.tokens[key]),
                reset_time=now + self.config.window_size_seconds,
                limit=limit,
                window_size=self.config.window_size_seconds
            )
        else:
            # Вычисляем время до следующего токена
            tokens_needed = 1 - self.tokens[key]
            time_to_next_token = tokens_needed * (self.config.window_size_seconds / limit)
            
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=now + time_to_next_token,
                retry_after=time_to_next_token,
                limit=limit,
                window_size=self.config.window_size_seconds
            )
    
    async def _check_leaky_bucket(self, key: str, limit: int) -> RateLimitResult:
        """Проверка с leaky bucket"""
        now = time.time()
        time_passed = now - self.last_update[key]
        
        # Утечка токенов
        leak_rate = limit / self.config.window_size_seconds
        leaked_tokens = time_passed * leak_rate
        self.tokens[key] = max(0, self.tokens[key] - leaked_tokens)
        self.last_update[key] = now
        
        # Проверяем лимит
        if self.tokens[key] < self.config.burst_limit:
            self.tokens[key] += 1
            return RateLimitResult(
                allowed=True,
                remaining=self.config.burst_limit - int(self.tokens[key]),
                reset_time=now + self.config.window_size_seconds,
                limit=limit,
                window_size=self.config.window_size_seconds
            )
        else:
            # Вычисляем время до освобождения места
            time_to_space = (self.tokens[key] - self.config.burst_limit + 1) / leak_rate
            
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=now + time_to_space,
                retry_after=time_to_space,
                limit=limit,
                window_size=self.config.window_size_seconds
            )
    
    async def _cleanup_old_entries(self):
        """Очистка старых записей"""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval_seconds)
                
                async with self.lock:
                    now = time.time()
                    cutoff_time = now - (self.config.window_size_seconds * 2)
                    
                    # Очищаем старые запросы
                    keys_to_remove = []
                    for key, requests in self.requests.items():
                        while requests and requests[0] < cutoff_time:
                            requests.popleft()
                        
                        if not requests:
                            keys_to_remove.append(key)
                    
                    for key in keys_to_remove:
                        del self.requests[key]
                        if key in self.tokens:
                            del self.tokens[key]
                        if key in self.last_update:
                            del self.last_update[key]
                    
                    logger.debug(
                        "rate_limiter_cleanup",
                        removed_keys=len(keys_to_remove),
                        active_keys=len(self.requests)
                    )
                    
            except Exception as e:
                logger.error(
                    "rate_limiter_cleanup_error",
                    error=str(e),
                    error_type=type(e).__name__
                )
    
    def get_stats(self) -> Dict[str, any]:
        """Получить статистику rate limiter"""
        return {
            "active_identifiers": len(self.requests),
            "total_requests": sum(len(requests) for requests in self.requests.values()),
            "strategy": self.config.strategy.value,
            "config": {
                "requests_per_minute": self.config.requests_per_minute,
                "requests_per_hour": self.config.requests_per_hour,
                "burst_limit": self.config.burst_limit,
                "window_size_seconds": self.config.window_size_seconds
            }
        }

# Глобальный экземпляр rate limiter
rate_limiter = EnhancedRateLimiter(RateLimitConfig())