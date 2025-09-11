"""
Connection Pool сервис для оптимизации производительности
Поддерживает PostgreSQL, Redis и HTTP соединения
"""

import asyncio
import logging
from typing import Dict, Optional, Any
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import asyncpg
from redis import asyncio as aioredis
import httpx
from dataclasses import dataclass

from config.settings import settings
from backend.core.exceptions import (
    DatabaseError, RedisError, NetworkError, 
    ConnectionError, TimeoutError, ConfigurationError
)

logger = logging.getLogger(__name__)

@dataclass
class PoolConfig:
    """Конфигурация пула соединений"""
    min_connections: int = 5
    max_connections: int = 20
    max_overflow: int = 30
    connection_timeout: int = 30
    command_timeout: int = 60
    idle_timeout: int = 300
    max_lifetime: int = 3600

class DatabaseConnectionPool:
    """Пул соединений для PostgreSQL"""
    
    def __init__(self, config: PoolConfig):
        self.config = config
        self.pool: Optional[asyncpg.Pool] = None
        self._initialized = False
    
    async def initialize(self, database_url: str):
        """Инициализирует пул соединений"""
        if self._initialized:
            return
        
        try:
            self.pool = await asyncpg.create_pool(
                database_url,
                min_size=self.config.min_connections,
                max_size=self.config.max_connections,
                max_queries=self.config.max_overflow,
                command_timeout=self.config.command_timeout,
                server_settings={
                    'application_name': 'samokoder_backend',
                    'timezone': 'UTC'
                }
            )
            self._initialized = True
            logger.info(f"Database connection pool initialized: {self.config.min_connections}-{self.config.max_connections} connections")
        except asyncpg.PostgresError as e:
            logger.error(f"PostgreSQL error initializing connection pool: {e}")
            raise DatabaseError(f"Database connection pool initialization failed: {e}")
        except ConnectionError as e:
            logger.error(f"Connection error initializing database pool: {e}")
            raise DatabaseError(f"Database connection pool initialization failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error initializing database pool: {e}")
            raise DatabaseError(f"Database connection pool initialization failed: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            raise DatabaseError(f"Database connection pool initialization failed: {e}")
    
    async def close(self):
        """Закрывает пул соединений"""
        if self.pool:
            await self.pool.close()
            self._initialized = False
            logger.info("Database connection pool closed")
    
    @asynccontextmanager
    async def acquire(self):
        """Получает соединение из пула"""
        if not self._initialized or not self.pool:
            raise RuntimeError("Connection pool not initialized")
        
        connection = None
        try:
            connection = await self.pool.acquire()
            yield connection
        finally:
            if connection:
                await self.pool.release(connection)
    
    async def execute(self, query: str, *args):
        """Выполняет запрос с автоматическим управлением соединением"""
        async with self.acquire() as conn:
            return await conn.execute(query, *args)
    
    async def fetch(self, query: str, *args):
        """Выполняет SELECT запрос"""
        async with self.acquire() as conn:
            return await conn.fetch(query, *args)
    
    async def fetchrow(self, query: str, *args):
        """Выполняет SELECT запрос и возвращает одну строку"""
        async with self.acquire() as conn:
            return await conn.fetchrow(query, *args)
    
    async def fetchval(self, query: str, *args):
        """Выполняет SELECT запрос и возвращает одно значение"""
        async with self.acquire() as conn:
            return await conn.fetchval(query, *args)
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику пула"""
        if not self.pool:
            return {"status": "not_initialized"}
        
        return {
            "status": "active",
            "size": self.pool.get_size(),
            "min_size": self.pool.get_min_size(),
            "max_size": self.pool.get_max_size(),
            "idle_connections": self.pool.get_idle_size(),
            "used_connections": self.pool.get_size() - self.pool.get_idle_size()
        }

class RedisConnectionPool:
    """Пул соединений для Redis"""
    
    def __init__(self, config: PoolConfig):
        self.config = config
        self.pool: Optional[aioredis.ConnectionPool] = None
        self.redis: Optional[aioredis.Redis] = None
        self._initialized = False
    
    async def initialize(self, redis_url: str):
        """Инициализирует пул соединений Redis"""
        if self._initialized:
            return
        
        try:
            self.pool = aioredis.ConnectionPool.from_url(
                redis_url,
                max_connections=self.config.max_connections,
                retry_on_timeout=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                health_check_interval=30
            )
            
            self.redis = aioredis.Redis(connection_pool=self.pool)
            
            # Проверяем соединение
            await self.redis.ping()
            
            self._initialized = True
            logger.info(f"Redis connection pool initialized: max {self.config.max_connections} connections")
        except aioredis.ConnectionError as e:
            logger.error(f"Redis connection error initializing pool: {e}")
            raise RedisError(f"Redis connection pool initialization failed: {e}")
        except aioredis.TimeoutError as e:
            logger.error(f"Redis timeout error initializing pool: {e}")
            raise RedisError(f"Redis connection pool initialization failed: {e}")
        except ConnectionError as e:
            logger.error(f"Connection error initializing Redis pool: {e}")
            raise RedisError(f"Redis connection pool initialization failed: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize Redis connection pool: {e}")
            raise RedisError(f"Redis connection pool initialization failed: {e}")
    
    async def close(self):
        """Закрывает пул соединений"""
        if self.redis:
            await self.redis.close()
        if self.pool:
            await self.pool.disconnect()
        self._initialized = False
        logger.info("Redis connection pool closed")
    
    async def get(self, key: str) -> Optional[str]:
        """Получает значение по ключу"""
        if not self._initialized or not self.redis:
            raise RuntimeError("Redis connection pool not initialized")
        return await self.redis.get(key)
    
    async def set(self, key: str, value: str, ex: Optional[int] = None):
        """Устанавливает значение"""
        if not self._initialized or not self.redis:
            raise RuntimeError("Redis connection pool not initialized")
        return await self.redis.set(key, value, ex=ex)
    
    async def delete(self, *keys: str) -> int:
        """Удаляет ключи"""
        if not self._initialized or not self.redis:
            raise RuntimeError("Redis connection pool not initialized")
        return await self.redis.delete(*keys)
    
    async def exists(self, key: str) -> bool:
        """Проверяет существование ключа"""
        if not self._initialized or not self.redis:
            raise RuntimeError("Redis connection pool not initialized")
        return await self.redis.exists(key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику пула"""
        if not self.pool:
            return {"status": "not_initialized"}
        
        return {
            "status": "active",
            "max_connections": self.config.max_connections,
            "connection_pool_size": len(self.pool._available_connections) if hasattr(self.pool, '_available_connections') else 0
        }

class HTTPConnectionPool:
    """Пул соединений для HTTP клиентов"""
    
    def __init__(self, config: PoolConfig):
        self.config = config
        self.client: Optional[httpx.AsyncClient] = None
        self._initialized = False
    
    async def initialize(self):
        """Инициализирует HTTP клиент с пулом соединений"""
        if self._initialized:
            return
        
        try:
            limits = httpx.Limits(
                max_keepalive_connections=self.config.max_connections,
                max_connections=self.config.max_connections + self.config.max_overflow,
                keepalive_expiry=self.config.idle_timeout
            )
            
            timeout = httpx.Timeout(
                connect=self.config.connection_timeout,
                read=self.config.command_timeout,
                write=self.config.command_timeout,
                pool=self.config.connection_timeout
            )
            
            self.client = httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                headers={
                    "User-Agent": "Samokoder-Backend/1.0.0"
                }
            )
            
            self._initialized = True
            logger.info(f"HTTP connection pool initialized: max {self.config.max_connections} connections")
        except httpx.ConnectError as e:
            logger.error(f"HTTP connection error initializing pool: {e}")
            raise NetworkError(f"HTTP connection pool initialization failed: {e}")
        except httpx.TimeoutException as e:
            logger.error(f"HTTP timeout error initializing pool: {e}")
            raise NetworkError(f"HTTP connection pool initialization failed: {e}")
        except ConnectionError as e:
            logger.error(f"Connection error initializing HTTP pool: {e}")
            raise NetworkError(f"HTTP connection pool initialization failed: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize HTTP connection pool: {e}")
            raise NetworkError(f"HTTP connection pool initialization failed: {e}")
    
    async def close(self):
        """Закрывает HTTP клиент"""
        if self.client:
            await self.client.aclose()
        self._initialized = False
        logger.info("HTTP connection pool closed")
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Выполняет GET запрос"""
        if not self._initialized or not self.client:
            raise RuntimeError("HTTP connection pool not initialized")
        return await self.client.get(url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Выполняет POST запрос"""
        if not self._initialized or not self.client:
            raise RuntimeError("HTTP connection pool not initialized")
        return await self.client.post(url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Выполняет PUT запрос"""
        if not self._initialized or not self.client:
            raise RuntimeError("HTTP connection pool not initialized")
        return await self.client.put(url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Выполняет DELETE запрос"""
        if not self._initialized or not self.client:
            raise RuntimeError("HTTP connection pool not initialized")
        return await self.client.delete(url, **kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику пула"""
        if not self.client:
            return {"status": "not_initialized"}
        
        return {
            "status": "active",
            "max_connections": self.config.max_connections,
            "max_overflow": self.config.max_overflow
        }

class ConnectionPoolManager:
    """Менеджер всех пулов соединений"""
    
    def __init__(self):
        self.config = PoolConfig(
            min_connections=settings.database_pool_size,
            max_connections=settings.database_pool_size + settings.database_max_overflow,
            max_overflow=settings.database_max_overflow,
            connection_timeout=30,
            command_timeout=60,
            idle_timeout=300,
            max_lifetime=3600
        )
        
        self.database_pool = DatabaseConnectionPool(self.config)
        self.redis_pool = RedisConnectionPool(self.config)
        self.http_pool = HTTPConnectionPool(self.config)
        
        self._initialized = False
    
    async def initialize_all(self):
        """Инициализирует все пулы соединений"""
        if self._initialized:
            return
        
        try:
            # Инициализируем пулы параллельно
            tasks = []
            
            if settings.database_url:
                tasks.append(self.database_pool.initialize(settings.database_url))
            
            if settings.redis_url:
                tasks.append(self.redis_pool.initialize(settings.redis_url))
            
            tasks.append(self.http_pool.initialize())
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            self._initialized = True
            logger.info("All connection pools initialized successfully")
            
        except DatabaseError as e:
            logger.error(f"Database error initializing connection pools: {e}")
            await self.close_all()
            raise
        except RedisError as e:
            logger.error(f"Redis error initializing connection pools: {e}")
            await self.close_all()
            raise
        except NetworkError as e:
            logger.error(f"Network error initializing connection pools: {e}")
            await self.close_all()
            raise
        except Exception as e:
            logger.error(f"Failed to initialize connection pools: {e}")
            await self.close_all()
            raise
    
    async def close_all(self):
        """Закрывает все пулы соединений"""
        tasks = [
            self.database_pool.close(),
            self.redis_pool.close(),
            self.http_pool.close()
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        self._initialized = False
        logger.info("All connection pools closed")
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Возвращает статистику всех пулов"""
        return {
            "database": self.database_pool.get_stats(),
            "redis": self.redis_pool.get_stats(),
            "http": self.http_pool.get_stats(),
            "initialized": self._initialized,
            "timestamp": datetime.now().isoformat()
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Проверяет здоровье всех пулов"""
        health_status = {
            "overall": "healthy",
            "pools": {},
            "timestamp": datetime.now().isoformat()
        }
        
        # Проверяем базу данных
        try:
            if self.database_pool._initialized:
                await self.database_pool.fetchval("SELECT 1")
                health_status["pools"]["database"] = "healthy"
            else:
                health_status["pools"]["database"] = "not_initialized"
        except asyncpg.PostgresError as e:
            health_status["pools"]["database"] = f"unhealthy: PostgreSQL error: {str(e)}"
            health_status["overall"] = "unhealthy"
        except ConnectionError as e:
            health_status["pools"]["database"] = f"unhealthy: Connection error: {str(e)}"
            health_status["overall"] = "unhealthy"
        except Exception as e:
            health_status["pools"]["database"] = f"unhealthy: {str(e)}"
            health_status["overall"] = "unhealthy"
        
        # Проверяем Redis
        try:
            if self.redis_pool._initialized:
                await self.redis_pool.redis.ping()
                health_status["pools"]["redis"] = "healthy"
            else:
                health_status["pools"]["redis"] = "not_initialized"
        except aioredis.ConnectionError as e:
            health_status["pools"]["redis"] = f"unhealthy: Redis connection error: {str(e)}"
            health_status["overall"] = "unhealthy"
        except aioredis.TimeoutError as e:
            health_status["pools"]["redis"] = f"unhealthy: Redis timeout: {str(e)}"
            health_status["overall"] = "unhealthy"
        except Exception as e:
            health_status["pools"]["redis"] = f"unhealthy: {str(e)}"
            health_status["overall"] = "unhealthy"
        
        # Проверяем HTTP пул
        try:
            if self.http_pool._initialized:
                health_status["pools"]["http"] = "healthy"
            else:
                health_status["pools"]["http"] = "not_initialized"
        except httpx.ConnectError as e:
            health_status["pools"]["http"] = f"unhealthy: HTTP connection error: {str(e)}"
            health_status["overall"] = "unhealthy"
        except httpx.TimeoutException as e:
            health_status["pools"]["http"] = f"unhealthy: HTTP timeout: {str(e)}"
            health_status["overall"] = "unhealthy"
        except Exception as e:
            health_status["pools"]["http"] = f"unhealthy: {str(e)}"
            health_status["overall"] = "unhealthy"
        
        return health_status

# Глобальный менеджер пулов соединений
connection_pool_manager = ConnectionPoolManager()

# Функции для удобного доступа
async def get_database_pool() -> DatabaseConnectionPool:
    """Получает пул соединений базы данных"""
    if not connection_pool_manager._initialized:
        await connection_pool_manager.initialize_all()
    return connection_pool_manager.database_pool

async def get_redis_pool() -> RedisConnectionPool:
    """Получает пул соединений Redis"""
    if not connection_pool_manager._initialized:
        await connection_pool_manager.initialize_all()
    return connection_pool_manager.redis_pool

async def get_http_pool() -> HTTPConnectionPool:
    """Получает пул HTTP соединений"""
    if not connection_pool_manager._initialized:
        await connection_pool_manager.initialize_all()
    return connection_pool_manager.http_pool

# Контекстные менеджеры для удобства
@asynccontextmanager
async def database_connection():
    """Контекстный менеджер для работы с базой данных"""
    pool = await get_database_pool()
    async with pool.acquire() as conn:
        yield conn

@asynccontextmanager
async def redis_connection():
    """Контекстный менеджер для работы с Redis"""
    pool = await get_redis_pool()
    yield pool