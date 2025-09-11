"""
Cache Service - Сервис кэширования для оптимизации производительности
Redis интеграция, кэширование AI запросов, кэширование проектов
"""

import json
import pickle
import hashlib
from datetime import datetime, timedelta
from typing import Any, Optional, Dict, List
import asyncio
import logging

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

from config.settings import settings

logger = logging.getLogger(__name__)

class CacheService:
    """Сервис кэширования с Redis"""
    
    def __init__(self):
        self.redis_client = None
        self.cache_enabled = False
        self._init_redis()
    
    def _init_redis(self):
        """Инициализация Redis клиента"""
        
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, caching disabled")
            return
        
        try:
            self.redis_client = redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=False  # Для бинарных данных
            )
            self.cache_enabled = True
            logger.info("Redis cache initialized successfully")
        except Exception as e:
            logger.error(f"Redis initialization failed: {e}")
            self.cache_enabled = False
    
    async def get(self, key: str) -> Optional[Any]:
        """Получение значения из кэша"""
        
        if not self.cache_enabled:
            return None
        
        try:
            data = await self.redis_client.get(key)
            if data:
                return pickle.loads(data)
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
        
        return None
    
    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Сохранение значения в кэш"""
        
        if not self.cache_enabled:
            return False
        
        try:
            data = pickle.dumps(value)
            await self.redis_client.setex(key, ttl, data)
            return True
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Удаление значения из кэша"""
        
        if not self.cache_enabled:
            return False
        
        try:
            await self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Проверка существования ключа в кэше"""
        
        if not self.cache_enabled:
            return False
        
        try:
            return await self.redis_client.exists(key)
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    async def clear_pattern(self, pattern: str) -> int:
        """Очистка кэша по паттерну"""
        
        if not self.cache_enabled:
            return 0
        
        try:
            keys = await self.redis_client.keys(pattern)
            if keys:
                return await self.redis_client.delete(*keys)
        except Exception as e:
            logger.error(f"Cache clear pattern error for {pattern}: {e}")
        
        return 0

class AIResponseCache:
    """Кэш для AI ответов"""
    
    def __init__(self, cache_service: CacheService):
        self.cache = cache_service
        self.default_ttl = 3600  # 1 час
    
    def _generate_key(self, messages: List[Dict], model: str, provider: str) -> str:
        """Генерация ключа кэша для AI запроса"""
        
        # Создаем хэш от содержимого запроса
        content = json.dumps({
            "messages": messages,
            "model": model,
            "provider": provider
        }, sort_keys=True)
        
        hash_obj = hashlib.sha256(content.encode())
        return f"ai_response:{hash_obj.hexdigest()}"
    
    async def get_cached_response(self, messages: List[Dict], model: str, provider: str) -> Optional[Dict]:
        """Получение кэшированного AI ответа"""
        
        key = self._generate_key(messages, model, provider)
        return await self.cache.get(key)
    
    async def cache_response(self, messages: List[Dict], model: str, provider: str, response: Dict, ttl: int = None) -> bool:
        """Кэширование AI ответа"""
        
        key = self._generate_key(messages, model, provider)
        return await self.cache.set(key, response, ttl or self.default_ttl)
    
    async def invalidate_user_cache(self, user_id: str):
        """Очистка кэша пользователя"""
        
        pattern = f"ai_response:*"
        await self.cache.clear_pattern(pattern)

class ProjectCache:
    """Кэш для проектов"""
    
    def __init__(self, cache_service: CacheService):
        self.cache = cache_service
        self.default_ttl = 1800  # 30 минут
    
    def _generate_key(self, project_id: str, data_type: str) -> str:
        """Генерация ключа кэша для проекта"""
        return f"project:{project_id}:{data_type}"
    
    async def get_project_info(self, project_id: str) -> Optional[Dict]:
        """Получение информации о проекте из кэша"""
        
        key = self._generate_key(project_id, "info")
        return await self.cache.get(key)
    
    async def cache_project_info(self, project_id: str, info: Dict, ttl: int = None) -> bool:
        """Кэширование информации о проекте"""
        
        key = self._generate_key(project_id, "info")
        return await self.cache.set(key, info, ttl or self.default_ttl)
    
    async def get_project_files(self, project_id: str) -> Optional[Dict]:
        """Получение файлов проекта из кэша"""
        
        key = self._generate_key(project_id, "files")
        return await self.cache.get(key)
    
    async def cache_project_files(self, project_id: str, files: Dict, ttl: int = None) -> bool:
        """Кэширование файлов проекта"""
        
        key = self._generate_key(project_id, "files")
        return await self.cache.set(key, files, ttl or self.default_ttl)
    
    async def invalidate_project_cache(self, project_id: str):
        """Очистка кэша проекта"""
        
        patterns = [
            f"project:{project_id}:info",
            f"project:{project_id}:files"
        ]
        
        for pattern in patterns:
            await self.cache.clear_pattern(pattern)

class UserCache:
    """Кэш для пользователей"""
    
    def __init__(self, cache_service: CacheService):
        self.cache = cache_service
        self.default_ttl = 1800  # 30 минут
    
    def _generate_key(self, user_id: str, data_type: str) -> str:
        """Генерация ключа кэша для пользователя"""
        return f"user:{user_id}:{data_type}"
    
    async def get_user_projects(self, user_id: str) -> Optional[List[Dict]]:
        """Получение проектов пользователя из кэша"""
        
        key = self._generate_key(user_id, "projects")
        return await self.cache.get(key)
    
    async def cache_user_projects(self, user_id: str, projects: List[Dict], ttl: int = None) -> bool:
        """Кэширование проектов пользователя"""
        
        key = self._generate_key(user_id, "projects")
        return await self.cache.set(key, projects, ttl or self.default_ttl)
    
    async def get_user_api_keys(self, user_id: str) -> Optional[Dict]:
        """Получение API ключей пользователя из кэша"""
        
        key = self._generate_key(user_id, "api_keys")
        return await self.cache.get(key)
    
    async def cache_user_api_keys(self, user_id: str, api_keys: Dict, ttl: int = None) -> bool:
        """Кэширование API ключей пользователя"""
        
        key = self._generate_key(user_id, "api_keys")
        return await self.cache.set(key, api_keys, ttl or self.default_ttl)
    
    async def invalidate_user_cache(self, user_id: str):
        """Очистка кэша пользователя"""
        
        patterns = [
            f"user:{user_id}:projects",
            f"user:{user_id}:api_keys"
        ]
        
        for pattern in patterns:
            await self.cache.clear_pattern(pattern)

class CacheManager:
    """Менеджер кэширования"""
    
    def __init__(self):
        self.cache_service = CacheService()
        self.ai_cache = AIResponseCache(self.cache_service)
        self.project_cache = ProjectCache(self.cache_service)
        self.user_cache = UserCache(self.cache_service)
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Получение статистики кэша"""
        
        if not self.cache_service.cache_enabled:
            return {
                "enabled": False,
                "redis_available": REDIS_AVAILABLE,
                "error": "Cache not enabled"
            }
        
        try:
            info = await self.cache_service.redis_client.info()
            return {
                "enabled": True,
                "redis_available": True,
                "used_memory": info.get("used_memory_human", "N/A"),
                "connected_clients": info.get("connected_clients", 0),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0)
            }
        except Exception as e:
            return {
                "enabled": True,
                "redis_available": True,
                "error": str(e)
            }
    
    async def clear_all_cache(self) -> bool:
        """Очистка всего кэша"""
        
        if not self.cache_service.cache_enabled:
            return False
        
        try:
            await self.cache_service.redis_client.flushdb()
            return True
        except Exception as e:
            logger.error(f"Clear all cache error: {e}")
            return False

# Глобальный экземпляр менеджера кэширования
cache_manager = CacheManager()

def get_cache_manager() -> CacheManager:
    """Получение экземпляра менеджера кэширования"""
    return cache_manager

# Декораторы для кэширования
def cache_result(ttl: int = 3600, key_prefix: str = ""):
    """Декоратор для кэширования результатов функций"""
    
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Генерируем ключ кэша
            cache_key = f"{key_prefix}:{func.__name__}:{hash(str(args) + str(kwargs))}"
            
            # Пытаемся получить из кэша
            cached_result = await cache_manager.cache_service.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Выполняем функцию
            result = await func(*args, **kwargs)
            
            # Сохраняем в кэш
            await cache_manager.cache_service.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    return decorator