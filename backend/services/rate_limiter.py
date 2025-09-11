"""
Rate Limiter сервис для защиты от DDoS атак и злоупотреблений
Поддерживает Redis и in-memory режимы
"""

import asyncio
import time
import json
from typing import Dict, Tuple, Optional
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from config.settings import settings
from backend.core.exceptions import (
    RedisError, NetworkError, TimeoutError, 
    ConfigurationError, CacheError
)

logger = logging.getLogger(__name__)

@dataclass
class RateLimitInfo:
    """Информация о rate limit"""
    minute_requests: int
    hour_requests: int
    minute_limit: int
    hour_limit: int
    minute_allowed: bool
    hour_allowed: bool
    reset_time_minute: int
    reset_time_hour: int

class RateLimiter:
    """
    Rate Limiter с поддержкой Redis и in-memory режимов
    """
    
    def __init__(self):
        self.redis_client = None
        self.memory_store = {}  # Fallback для in-memory режима
        self._redis_initialized = False
    
    def _init_redis(self):
        """Инициализация Redis клиента"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, using in-memory rate limiting")
            return
        
        try:
            self.redis_client = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            logger.info("Redis rate limiter initialized")
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection failed: {e}, using in-memory rate limiting")
            self.redis_client = None
        except redis.TimeoutError as e:
            logger.warning(f"Redis timeout: {e}, using in-memory rate limiting")
            self.redis_client = None
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}, using in-memory rate limiting")
            self.redis_client = None
    
    async def _ensure_redis_initialized(self):
        """Обеспечивает инициализацию Redis клиента"""
        if not self._redis_initialized:
            await self._init_redis_async()
            self._redis_initialized = True

    async def _init_redis_async(self):
        """Асинхронная инициализация Redis клиента"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, using in-memory rate limiting")
            return
        
        try:
            self.redis_client = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            # Тестируем подключение
            await self.redis_client.ping()
            logger.info("Redis rate limiter initialized")
        except redis.ConnectionError as e:
            logger.warning(f"Redis connection failed: {e}, using in-memory rate limiting")
            self.redis_client = None
        except redis.TimeoutError as e:
            logger.warning(f"Redis timeout: {e}, using in-memory rate limiting")
            self.redis_client = None
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}, using in-memory rate limiting")
            self.redis_client = None

    async def check_rate_limit(
        self,
        user_id: str,
        endpoint: str,
        limit_per_minute: int = 60,
        limit_per_hour: int = 1000
    ) -> Tuple[bool, RateLimitInfo]:
        """
        Проверяет rate limit для пользователя и эндпоинта
        
        Returns:
            Tuple[bool, RateLimitInfo]: (разрешен ли запрос, информация о лимитах)
        """
        await self._ensure_redis_initialized()
        
        current_time = int(time.time())
        minute_key = f"rate_limit:{user_id}:{endpoint}:minute:{current_time // 60}"
        hour_key = f"rate_limit:{user_id}:{endpoint}:hour:{current_time // 3600}"
        
        if self.redis_client:
            return await self._check_redis_rate_limit(
                minute_key, hour_key, limit_per_minute, limit_per_hour, current_time
            )
        else:
            return await self._check_memory_rate_limit(
                user_id, endpoint, limit_per_minute, limit_per_hour, current_time
            )
    
    async def _check_redis_rate_limit(
        self,
        minute_key: str,
        hour_key: str,
        limit_per_minute: int,
        limit_per_hour: int,
        current_time: int
    ) -> Tuple[bool, RateLimitInfo]:
        """Проверка rate limit через Redis"""
        try:
            # Используем pipeline для атомарности операций
            pipe = self.redis_client.pipeline()
            
            # Увеличиваем счетчики
            pipe.incr(minute_key)
            pipe.incr(hour_key)
            
            # Устанавливаем TTL
            pipe.expire(minute_key, 60)  # 1 минута
            pipe.expire(hour_key, 3600)  # 1 час
            
            # Получаем значения
            pipe.get(minute_key)
            pipe.get(hour_key)
            
            results = await pipe.execute()
            
            # results[0] = incr(minute_key), results[1] = incr(hour_key)
            # results[2] = expire(minute_key), results[3] = expire(hour_key)  
            # results[4] = get(minute_key), results[5] = get(hour_key)
            minute_requests = int(results[0] or 0)  # incr результат
            hour_requests = int(results[1] or 0)    # incr результат
            
            minute_allowed = minute_requests <= limit_per_minute
            hour_allowed = hour_requests <= limit_per_hour
            
            allowed = minute_allowed and hour_allowed
            
            rate_info = RateLimitInfo(
                minute_requests=minute_requests,
                hour_requests=hour_requests,
                minute_limit=limit_per_minute,
                hour_limit=limit_per_hour,
                minute_allowed=minute_allowed,
                hour_allowed=hour_allowed,
                reset_time_minute=current_time + 60,
                reset_time_hour=current_time + 3600
            )
            
            return allowed, rate_info
            
        except redis.ConnectionError as e:
            logger.error(f"Redis connection error in rate limit: {e}")
            # Fallback на memory режим
            return await self._check_memory_rate_limit(
                "fallback", "fallback", limit_per_minute, limit_per_hour, current_time
            )
        except redis.TimeoutError as e:
            logger.error(f"Redis timeout in rate limit: {e}")
            # Fallback на memory режим
            return await self._check_memory_rate_limit(
                "fallback", "fallback", limit_per_minute, limit_per_hour, current_time
            )
        except Exception as e:
            logger.error(f"Redis rate limit error: {e}")
            # Fallback на memory режим
            return await self._check_memory_rate_limit(
                "fallback", "fallback", limit_per_minute, limit_per_hour, current_time
            )
    
    async def _check_memory_rate_limit(
        self,
        user_id: str,
        endpoint: str,
        limit_per_minute: int,
        limit_per_hour: int,
        current_time: int
    ) -> Tuple[bool, RateLimitInfo]:
        """Проверка rate limit в памяти"""
        key = f"{user_id}:{endpoint}"
        current_minute = current_time // 60
        current_hour = current_time // 3600
        
        # Инициализируем структуру данных если нужно
        if key not in self.memory_store:
            self.memory_store[key] = {
                'minute': {'count': 0, 'window': current_minute},
                'hour': {'count': 0, 'window': current_hour}
            }
        
        store = self.memory_store[key]
        
        # Сбрасываем счетчики если окно изменилось
        if store['minute']['window'] != current_minute:
            store['minute'] = {'count': 0, 'window': current_minute}
        
        if store['hour']['window'] != current_hour:
            store['hour'] = {'count': 0, 'window': current_hour}
        
        # Увеличиваем счетчики
        store['minute']['count'] += 1
        store['hour']['count'] += 1
        
        minute_requests = store['minute']['count']
        hour_requests = store['hour']['count']
        
        minute_allowed = minute_requests <= limit_per_minute
        hour_allowed = hour_requests <= limit_per_hour
        
        allowed = minute_allowed and hour_allowed
        
        rate_info = RateLimitInfo(
            minute_requests=minute_requests,
            hour_requests=hour_requests,
            minute_limit=limit_per_minute,
            hour_limit=limit_per_hour,
            minute_allowed=minute_allowed,
            hour_allowed=hour_allowed,
            reset_time_minute=current_time + 60,
            reset_time_hour=current_time + 3600
        )
        
        return allowed, rate_info
    
    async def get_rate_limit_info(
        self,
        user_id: str,
        endpoint: str
    ) -> Optional[RateLimitInfo]:
        """Получает информацию о текущих лимитах без увеличения счетчика"""
        current_time = int(time.time())
        minute_key = f"rate_limit:{user_id}:{endpoint}:minute:{current_time // 60}"
        hour_key = f"rate_limit:{user_id}:{endpoint}:hour:{current_time // 3600}"
        
        if self.redis_client:
            try:
                minute_requests = await self.redis_client.get(minute_key)
                hour_requests = await self.redis_client.get(hour_key)
                
                return RateLimitInfo(
                    minute_requests=int(minute_requests or 0),
                    hour_requests=int(hour_requests or 0),
                    minute_limit=60,  # Default limits
                    hour_limit=1000,
                    minute_allowed=True,
                    hour_allowed=True,
                    reset_time_minute=current_time + 60,
                    reset_time_hour=current_time + 3600
                )
            except redis.ConnectionError as e:
                logger.error(f"Redis connection error getting rate limit info: {e}")
                return None
            except redis.TimeoutError as e:
                logger.error(f"Redis timeout getting rate limit info: {e}")
                return None
            except Exception as e:
                logger.error(f"Redis get rate limit info error: {e}")
                return None
        else:
            # Memory mode
            key = f"{user_id}:{endpoint}"
            if key in self.memory_store:
                store = self.memory_store[key]
                return RateLimitInfo(
                    minute_requests=store['minute']['count'],
                    hour_requests=store['hour']['count'],
                    minute_limit=60,
                    hour_limit=1000,
                    minute_allowed=True,
                    hour_allowed=True,
                    reset_time_minute=current_time + 60,
                    reset_time_hour=current_time + 3600
                )
            return None
    
    async def reset_rate_limit(self, user_id: str, endpoint: str):
        """Сбрасывает rate limit для пользователя и эндпоинта"""
        current_time = int(time.time())
        minute_key = f"rate_limit:{user_id}:{endpoint}:minute:{current_time // 60}"
        hour_key = f"rate_limit:{user_id}:{endpoint}:hour:{current_time // 3600}"
        
        if self.redis_client:
            try:
                await self.redis_client.delete(minute_key, hour_key)
                logger.info(f"Rate limit reset for {user_id}:{endpoint}")
            except redis.ConnectionError as e:
                logger.error(f"Redis connection error resetting rate limit: {e}")
            except redis.TimeoutError as e:
                logger.error(f"Redis timeout resetting rate limit: {e}")
            except Exception as e:
                logger.error(f"Redis reset rate limit error: {e}")
        else:
            # Memory mode
            key = f"{user_id}:{endpoint}"
            if key in self.memory_store:
                del self.memory_store[key]
                logger.info(f"Rate limit reset for {user_id}:{endpoint}")
    
    async def cleanup_expired_entries(self):
        """Очищает устаревшие записи (только для memory режима)"""
        if self.redis_client:
            return  # Redis автоматически удаляет записи по TTL
        
        current_time = int(time.time())
        current_minute = current_time // 60
        current_hour = current_time // 3600
        
        keys_to_remove = []
        for key, store in self.memory_store.items():
            if (store['minute']['window'] < current_minute - 1 or 
                store['hour']['window'] < current_hour - 1):
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.memory_store[key]
        
        if keys_to_remove:
            logger.info(f"Cleaned up {len(keys_to_remove)} expired rate limit entries")

# Глобальный экземпляр rate limiter
rate_limiter = RateLimiter()

# Функция для периодической очистки
async def cleanup_rate_limits():
    """Периодическая очистка устаревших записей"""
    while True:
        try:
            await asyncio.sleep(300)  # Каждые 5 минут
            await rate_limiter.cleanup_expired_entries()
        except Exception as e:
            logger.error(f"Rate limit cleanup error: {e}")

# Запуск фоновой задачи очистки
if not REDIS_AVAILABLE:
    asyncio.create_task(cleanup_rate_limits())