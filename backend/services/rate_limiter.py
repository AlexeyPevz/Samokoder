"""
Rate Limiting сервис для API
Использует Redis для хранения счетчиков и лимитов
"""

import asyncio
import json
import time
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import redis
import logging

from config.settings import settings

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Rate Limiter с поддержкой Redis и in-memory fallback
    """
    
    def __init__(self):
        self.redis_client = None
        self.memory_store = {}  # Fallback для случаев когда Redis недоступен
        
        # Инициализируем Redis если доступен
        try:
            self.redis_client = redis.from_url(settings.redis_url)
            # Проверяем подключение
            self.redis_client.ping()
            logger.info("Rate limiter using Redis")
        except Exception as e:
            logger.warning(f"Redis not available, using memory store: {e}")
            self.redis_client = None
    
    async def check_rate_limit(
        self, 
        user_id: str, 
        endpoint: str, 
        limit_per_minute: int = 60,
        limit_per_hour: int = 1000
    ) -> Tuple[bool, Dict[str, any]]:
        """
        Проверяет rate limit для пользователя и эндпоинта
        
        Returns:
            (is_allowed, rate_info)
        """
        
        current_time = int(time.time())
        minute_key = f"rate_limit:{user_id}:{endpoint}:minute:{current_time // 60}"
        hour_key = f"rate_limit:{user_id}:{endpoint}:hour:{current_time // 3600}"
        
        try:
            if self.redis_client:
                return await self._check_redis_rate_limit(
                    minute_key, hour_key, limit_per_minute, limit_per_hour
                )
            else:
                return await self._check_memory_rate_limit(
                    user_id, endpoint, limit_per_minute, limit_per_hour
                )
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # В случае ошибки разрешаем запрос
            return True, {
                "allowed": True,
                "minute_requests": 0,
                "hour_requests": 0,
                "minute_limit": limit_per_minute,
                "hour_limit": limit_per_hour,
                "error": str(e)
            }
    
    async def _check_redis_rate_limit(
        self, 
        minute_key: str, 
        hour_key: str, 
        limit_per_minute: int, 
        limit_per_hour: int
    ) -> Tuple[bool, Dict[str, any]]:
        """Проверка rate limit через Redis"""
        
        pipe = self.redis_client.pipeline()
        
        # Получаем текущие счетчики
        pipe.get(minute_key)
        pipe.get(hour_key)
        
        # Увеличиваем счетчики
        pipe.incr(minute_key)
        pipe.incr(hour_key)
        
        # Устанавливаем TTL
        pipe.expire(minute_key, 60)  # 1 минута
        pipe.expire(hour_key, 3600)  # 1 час
        
        results = pipe.execute()
        
        minute_requests = int(results[0] or 0) + 1
        hour_requests = int(results[1] or 0) + 1
        
        # Проверяем лимиты
        minute_allowed = minute_requests <= limit_per_minute
        hour_allowed = hour_requests <= limit_per_hour
        
        allowed = minute_allowed and hour_allowed
        
        return allowed, {
            "allowed": allowed,
            "minute_requests": minute_requests,
            "hour_requests": hour_requests,
            "minute_limit": limit_per_minute,
            "hour_limit": limit_per_hour,
            "minute_allowed": minute_allowed,
            "hour_allowed": hour_allowed
        }
    
    async def _check_memory_rate_limit(
        self, 
        user_id: str, 
        endpoint: str, 
        limit_per_minute: int, 
        limit_per_hour: int
    ) -> Tuple[bool, Dict[str, any]]:
        """Проверка rate limit через память (fallback)"""
        
        current_time = time.time()
        minute_window = int(current_time // 60)
        hour_window = int(current_time // 3600)
        
        # Очищаем старые записи
        self._cleanup_memory_store(current_time)
        
        # Ключи для хранения
        minute_key = f"{user_id}:{endpoint}:minute:{minute_window}"
        hour_key = f"{user_id}:{endpoint}:hour:{hour_window}"
        
        # Получаем текущие счетчики
        minute_requests = self.memory_store.get(minute_key, 0) + 1
        hour_requests = self.memory_store.get(hour_key, 0) + 1
        
        # Обновляем счетчики
        self.memory_store[minute_key] = minute_requests
        self.memory_store[hour_key] = hour_requests
        
        # Проверяем лимиты
        minute_allowed = minute_requests <= limit_per_minute
        hour_allowed = hour_requests <= limit_per_hour
        
        allowed = minute_allowed and hour_allowed
        
        return allowed, {
            "allowed": allowed,
            "minute_requests": minute_requests,
            "hour_requests": hour_requests,
            "minute_limit": limit_per_minute,
            "hour_limit": limit_per_hour,
            "minute_allowed": minute_allowed,
            "hour_allowed": hour_allowed
        }
    
    def _cleanup_memory_store(self, current_time: float):
        """Очищает старые записи из memory store"""
        
        current_minute = int(current_time // 60)
        current_hour = int(current_time // 3600)
        
        # Удаляем записи старше 2 часов
        keys_to_remove = []
        for key in self.memory_store.keys():
            if ":minute:" in key:
                minute = int(key.split(":")[-1])
                if minute < current_minute - 2:
                    keys_to_remove.append(key)
            elif ":hour:" in key:
                hour = int(key.split(":")[-1])
                if hour < current_hour - 2:
                    keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.memory_store[key]
    
    async def get_rate_limit_info(self, user_id: str, endpoint: str) -> Dict[str, any]:
        """Получает информацию о текущих лимитах пользователя"""
        
        current_time = int(time.time())
        minute_key = f"rate_limit:{user_id}:{endpoint}:minute:{current_time // 60}"
        hour_key = f"rate_limit:{user_id}:{endpoint}:hour:{current_time // 3600}"
        
        try:
            if self.redis_client:
                minute_requests = int(self.redis_client.get(minute_key) or 0)
                hour_requests = int(self.redis_client.get(hour_key) or 0)
            else:
                minute_window = int(current_time // 60)
                hour_window = int(current_time // 3600)
                minute_key_mem = f"{user_id}:{endpoint}:minute:{minute_window}"
                hour_key_mem = f"{user_id}:{endpoint}:hour:{hour_window}"
                minute_requests = self.memory_store.get(minute_key_mem, 0)
                hour_requests = self.memory_store.get(hour_key_mem, 0)
            
            return {
                "user_id": user_id,
                "endpoint": endpoint,
                "minute_requests": minute_requests,
                "hour_requests": hour_requests,
                "timestamp": current_time
            }
            
        except Exception as e:
            logger.error(f"Failed to get rate limit info: {e}")
            return {
                "user_id": user_id,
                "endpoint": endpoint,
                "minute_requests": 0,
                "hour_requests": 0,
                "timestamp": current_time,
                "error": str(e)
            }

# Глобальный экземпляр rate limiter
rate_limiter = RateLimiter()