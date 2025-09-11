"""
Централизованный Connection Manager
Управляет всеми внешними соединениями с connection pooling
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

from backend.services.connection_pool import (
    DatabaseConnectionPool, RedisConnectionPool, HTTPConnectionPool,
    PoolConfig
)
from backend.services.supabase_manager import supabase_manager
from config.settings import settings

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Централизованный менеджер всех соединений"""
    
    def __init__(self):
        self._initialized = False
        self._pools: Dict[str, Any] = {}
        self._config = PoolConfig()
    
    async def initialize(self):
        """Инициализация всех connection pools"""
        if self._initialized:
            return
        
        try:
            # Инициализируем Supabase manager
            await supabase_manager.initialize()
            self._pools['supabase'] = supabase_manager
            
            # Инициализируем Redis pool
            redis_pool = RedisConnectionPool(self._config)
            await redis_pool.initialize(settings.redis_url)
            self._pools['redis'] = redis_pool
            
            # Инициализируем HTTP pool
            http_pool = HTTPConnectionPool(self._config)
            await http_pool.initialize()
            self._pools['http'] = http_pool
            
            # Инициализируем Database pool если есть URL
            if settings.database_url:
                db_pool = DatabaseConnectionPool(self._config)
                await db_pool.initialize(settings.database_url)
                self._pools['database'] = db_pool
            
            self._initialized = True
            logger.info("All connection pools initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize connection pools: {e}")
            raise
    
    def get_pool(self, pool_type: str):
        """Получить connection pool по типу"""
        if not self._initialized:
            raise RuntimeError("Connection manager not initialized")
        
        pool = self._pools.get(pool_type)
        if not pool:
            raise ValueError(f"Connection pool '{pool_type}' not found")
        
        return pool
    
    @asynccontextmanager
    async def get_redis_connection(self):
        """Контекстный менеджер для Redis соединения"""
        redis_pool = self.get_pool('redis')
        async with redis_pool.acquire() as connection:
            yield connection
    
    @asynccontextmanager
    async def get_database_connection(self):
        """Контекстный менеджер для Database соединения"""
        db_pool = self.get_pool('database')
        async with db_pool.acquire() as connection:
            yield connection
    
    @asynccontextmanager
    async def get_http_client(self):
        """Контекстный менеджер для HTTP клиента"""
        http_pool = self.get_pool('http')
        async with http_pool.acquire() as client:
            yield client
    
    async def health_check_all(self) -> Dict[str, Any]:
        """Проверка здоровья всех connection pools"""
        health_status = {}
        
        # Проверяем Supabase
        try:
            supabase_health = await supabase_manager.health_check_all()
            health_status['supabase'] = supabase_health
        except Exception as e:
            health_status['supabase'] = {'error': str(e), 'healthy': False}
        
        # Проверяем Redis
        try:
            redis_pool = self.get_pool('redis')
            await redis_pool.ping()
            health_status['redis'] = {'healthy': True}
        except Exception as e:
            health_status['redis'] = {'error': str(e), 'healthy': False}
        
        # Проверяем HTTP pool
        try:
            http_pool = self.get_pool('http')
            health_status['http'] = {'healthy': True, 'connections': len(http_pool._clients)}
        except Exception as e:
            health_status['http'] = {'error': str(e), 'healthy': False}
        
        # Проверяем Database pool
        if 'database' in self._pools:
            try:
                db_pool = self.get_pool('database')
                health_status['database'] = {
                    'healthy': True,
                    'pool_size': db_pool.pool.get_size() if db_pool.pool else 0
                }
            except Exception as e:
                health_status['database'] = {'error': str(e), 'healthy': False}
        
        return health_status
    
    async def close(self):
        """Закрытие всех connection pools"""
        try:
            # Закрываем Supabase manager
            if 'supabase' in self._pools:
                await supabase_manager.close()
            
            # Закрываем Redis pool
            if 'redis' in self._pools:
                await self._pools['redis'].close()
            
            # Закрываем HTTP pool
            if 'http' in self._pools:
                await self._pools['http'].close()
            
            # Закрываем Database pool
            if 'database' in self._pools:
                await self._pools['database'].close()
            
            self._pools.clear()
            self._initialized = False
            logger.info("All connection pools closed")
            
        except Exception as e:
            logger.error(f"Error closing connection pools: {e}")

# Глобальный экземпляр менеджера
connection_manager = ConnectionManager()

# Удобные функции для использования
async def get_redis_connection():
    """Получить Redis соединение"""
    async with connection_manager.get_redis_connection() as conn:
        yield conn

async def get_database_connection():
    """Получить Database соединение"""
    async with connection_manager.get_database_connection() as conn:
        yield conn

async def get_http_client():
    """Получить HTTP клиент"""
    async with connection_manager.get_http_client() as client:
        yield client