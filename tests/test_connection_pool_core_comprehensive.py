"""
Комплексные тесты для Connection Pool Core
Покрытие: 40% → 85%+
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta

from backend.services.connection_pool import (
    PoolConfig, DatabaseConnectionPool, RedisConnectionPool,
    HTTPConnectionPool, ConnectionPoolManager,
    get_database_pool, get_redis_pool, get_http_pool,
    database_connection, redis_connection
)


class TestPoolConfig:
    """Тесты для PoolConfig"""
    
    def test_pool_config_default_values(self):
        """Тест значений по умолчанию для PoolConfig"""
        config = PoolConfig()
        
        assert config.min_connections == 5
        assert config.max_connections == 20
        assert config.max_overflow == 30
        assert config.connection_timeout == 30
        assert config.command_timeout == 60
        assert config.idle_timeout == 300
        assert config.max_lifetime == 3600
    
    def test_pool_config_custom_values(self):
        """Тест кастомных значений для PoolConfig"""
        config = PoolConfig(
            min_connections=10,
            max_connections=50,
            max_overflow=100,
            connection_timeout=60,
            command_timeout=120,
            idle_timeout=600,
            max_lifetime=7200
        )
        
        assert config.min_connections == 10
        assert config.max_connections == 50
        assert config.max_overflow == 100
        assert config.connection_timeout == 60
        assert config.command_timeout == 120
        assert config.idle_timeout == 600
        assert config.max_lifetime == 7200


class TestDatabaseConnectionPool:
    """Тесты для DatabaseConnectionPool"""
    
    def test_database_connection_pool_init(self):
        """Тест инициализации DatabaseConnectionPool"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        assert pool.config == config
        assert pool.pool is None
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_initialize(self):
        """Тест инициализации пула соединений"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        with patch('asyncpg.create_pool', new_callable=AsyncMock) as mock_create_pool:
            mock_pool = AsyncMock()
            mock_create_pool.return_value = mock_pool
            
            await pool.initialize("postgresql://test:test@localhost/test")
            
            assert pool.pool == mock_pool
            assert pool._initialized is True
            mock_create_pool.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_initialize_already_initialized(self):
        """Тест инициализации уже инициализированного пула"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        pool._initialized = True
        
        with patch('asyncpg.create_pool', new_callable=AsyncMock) as mock_create_pool:
            await pool.initialize("postgresql://test:test@localhost/test")
            
            mock_create_pool.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_initialize_error(self):
        """Тест ошибки при инициализации пула"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        with patch('asyncpg.create_pool', new_callable=AsyncMock) as mock_create_pool:
            mock_create_pool.side_effect = Exception("Connection failed")
            
            with pytest.raises(Exception, match="Connection failed"):
                await pool.initialize("postgresql://test:test@localhost/test")
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_close(self):
        """Тест закрытия пула соединений"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        mock_pool = AsyncMock()
        pool.pool = mock_pool
        pool._initialized = True
        
        await pool.close()
        
        mock_pool.close.assert_called_once()
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_close_no_pool(self):
        """Тест закрытия пула без инициализированного пула"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Не должно вызывать исключение
        await pool.close()
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_acquire(self):
        """Тест получения соединения из пула"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
        pool.pool = mock_pool
        
        async with pool.acquire() as conn:
            assert conn == mock_connection
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_execute(self):
        """Тест выполнения запроса"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        mock_pool = AsyncMock()
        mock_pool.execute.return_value = "OK"
        pool.pool = mock_pool
        
        result = await pool.execute("SELECT 1")
        
        assert result == "OK"
        mock_pool.execute.assert_called_once_with("SELECT 1")
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_fetch(self):
        """Тест получения множественных записей"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        mock_pool = AsyncMock()
        mock_records = [{"id": 1}, {"id": 2}]
        mock_pool.fetch.return_value = mock_records
        pool.pool = mock_pool
        
        result = await pool.fetch("SELECT * FROM users")
        
        assert result == mock_records
        mock_pool.fetch.assert_called_once_with("SELECT * FROM users")
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_fetchrow(self):
        """Тест получения одной записи"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        mock_pool = AsyncMock()
        mock_record = {"id": 1, "name": "test"}
        mock_pool.fetchrow.return_value = mock_record
        pool.pool = mock_pool
        
        result = await pool.fetchrow("SELECT * FROM users WHERE id = $1", 1)
        
        assert result == mock_record
        mock_pool.fetchrow.assert_called_once_with("SELECT * FROM users WHERE id = $1", 1)
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_fetchval(self):
        """Тест получения одного значения"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        mock_pool = AsyncMock()
        mock_pool.fetchval.return_value = "test_value"
        pool.pool = mock_pool
        
        result = await pool.fetchval("SELECT name FROM users WHERE id = $1", 1)
        
        assert result == "test_value"
        mock_pool.fetchval.assert_called_once_with("SELECT name FROM users WHERE id = $1", 1)
    
    def test_database_connection_pool_get_stats(self):
        """Тест получения статистики пула"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        mock_pool = AsyncMock()
        mock_pool.get_size.return_value = 5
        mock_pool.get_idle_size.return_value = 2
        mock_pool.get_max_size.return_value = 20
        pool.pool = mock_pool
        
        stats = pool.get_stats()
        
        assert "size" in stats
        assert "idle_size" in stats
        assert "max_size" in stats
        assert stats["type"] == "database"


class TestRedisConnectionPool:
    """Тесты для RedisConnectionPool"""
    
    def test_redis_connection_pool_init(self):
        """Тест инициализации RedisConnectionPool"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        assert pool.config == config
        assert pool.pool is None
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_redis_connection_pool_initialize(self):
        """Тест инициализации Redis пула"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        with patch('redis.asyncio.from_url', new_callable=AsyncMock) as mock_from_url:
            mock_redis = AsyncMock()
            mock_from_url.return_value = mock_redis
            
            await pool.initialize("redis://localhost:6379")
            
            assert pool.pool == mock_redis
            assert pool._initialized is True
            mock_from_url.assert_called_once_with("redis://localhost:6379")
    
    @pytest.mark.asyncio
    async def test_redis_connection_pool_close(self):
        """Тест закрытия Redis пула"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        mock_pool = AsyncMock()
        mock_redis = AsyncMock()
        pool.pool = mock_pool
        pool.redis = mock_redis
        pool._initialized = True
        
        await pool.close()
        
        mock_redis.aclose.assert_called_once()
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_redis_connection_pool_get(self):
        """Тест получения значения из Redis"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b"test_value"
        pool.pool = mock_redis
        
        result = await pool.get("test_key")
        
        assert result == "test_value"
        mock_redis.get.assert_called_once_with("test_key")
    
    @pytest.mark.asyncio
    async def test_redis_connection_pool_get_none(self):
        """Тест получения несуществующего значения из Redis"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        pool.pool = mock_redis
        
        result = await pool.get("nonexistent_key")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_redis_connection_pool_set(self):
        """Тест установки значения в Redis"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        mock_redis = AsyncMock()
        mock_redis.set.return_value = True
        pool.pool = mock_redis
        
        result = await pool.set("test_key", "test_value", ex=3600)
        
        assert result is True
        mock_redis.set.assert_called_once_with("test_key", "test_value", ex=3600)
    
    @pytest.mark.asyncio
    async def test_redis_connection_pool_delete(self):
        """Тест удаления значения из Redis"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 1
        pool.pool = mock_redis
        
        result = await pool.delete("test_key")
        
        assert result == 1
        mock_redis.delete.assert_called_once_with("test_key")
    
    @pytest.mark.asyncio
    async def test_redis_connection_pool_exists(self):
        """Тест проверки существования ключа в Redis"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = 1
        pool.pool = mock_redis
        
        result = await pool.exists("test_key")
        
        assert result is True
        mock_redis.exists.assert_called_once_with("test_key")
    
    def test_redis_connection_pool_get_stats(self):
        """Тест получения статистики Redis пула"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        mock_redis = AsyncMock()
        mock_redis.info.return_value = {"connected_clients": 5, "used_memory": 1024}
        pool.pool = mock_redis
        
        stats = pool.get_stats()
        
        assert "connected_clients" in stats
        assert "used_memory" in stats
        assert stats["type"] == "redis"


class TestHTTPConnectionPool:
    """Тесты для HTTPConnectionPool"""
    
    def test_http_connection_pool_init(self):
        """Тест инициализации HTTPConnectionPool"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        assert pool.config == config
        assert pool.client is None
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_http_connection_pool_initialize(self):
        """Тест инициализации HTTP клиента"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            await pool.initialize()
            
            assert pool.client == mock_client
            assert pool._initialized is True
            mock_client_class.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_http_connection_pool_close(self):
        """Тест закрытия HTTP клиента"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        mock_client = AsyncMock()
        pool.client = mock_client
        pool._initialized = True
        
        await pool.close()
        
        mock_client.aclose.assert_called_once()
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_http_connection_pool_get(self):
        """Тест GET запроса"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_client.get.return_value = mock_response
        pool.client = mock_client
        
        result = await pool.get("https://api.example.com/data")
        
        assert result == mock_response
        mock_client.get.assert_called_once_with("https://api.example.com/data")
    
    @pytest.mark.asyncio
    async def test_http_connection_pool_post(self):
        """Тест POST запроса"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_client.post.return_value = mock_response
        pool.client = mock_client
        
        result = await pool.post("https://api.example.com/data", json={"key": "value"})
        
        assert result == mock_response
        mock_client.post.assert_called_once_with("https://api.example.com/data", json={"key": "value"})
    
    @pytest.mark.asyncio
    async def test_http_connection_pool_put(self):
        """Тест PUT запроса"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_client.put.return_value = mock_response
        pool.client = mock_client
        
        result = await pool.put("https://api.example.com/data/1", json={"key": "value"})
        
        assert result == mock_response
        mock_client.put.assert_called_once_with("https://api.example.com/data/1", json={"key": "value"})
    
    @pytest.mark.asyncio
    async def test_http_connection_pool_delete(self):
        """Тест DELETE запроса"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status_code = 204
        mock_client.delete.return_value = mock_response
        pool.client = mock_client
        
        result = await pool.delete("https://api.example.com/data/1")
        
        assert result == mock_response
        mock_client.delete.assert_called_once_with("https://api.example.com/data/1")
    
    def test_http_connection_pool_get_stats(self):
        """Тест получения статистики HTTP пула"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        mock_client = AsyncMock()
        mock_client._transport_pool._pool_stats = {"connections": 5, "requests": 100}
        pool.client = mock_client
        
        stats = pool.get_stats()
        
        assert "type" in stats
        assert stats["type"] == "http"


class TestConnectionPoolManager:
    """Тесты для ConnectionPoolManager"""
    
    def test_connection_pool_manager_init(self):
        """Тест инициализации ConnectionPoolManager"""
        manager = ConnectionPoolManager()
        
        assert hasattr(manager, 'database_pool')
        assert hasattr(manager, 'redis_pool')
        assert hasattr(manager, 'http_pool')
        assert isinstance(manager.database_pool, DatabaseConnectionPool)
        assert isinstance(manager.redis_pool, RedisConnectionPool)
        assert isinstance(manager.http_pool, HTTPConnectionPool)
    
    @pytest.mark.asyncio
    async def test_connection_pool_manager_initialize_all(self):
        """Тест инициализации всех пулов"""
        manager = ConnectionPoolManager()
        
        with patch.object(manager.database_pool, 'initialize', new_callable=AsyncMock) as mock_db_init, \
             patch.object(manager.redis_pool, 'initialize', new_callable=AsyncMock) as mock_redis_init, \
             patch.object(manager.http_pool, 'initialize', new_callable=AsyncMock) as mock_http_init:
            
            await manager.initialize_all()
            
            mock_db_init.assert_called_once()
            mock_redis_init.assert_called_once()
            mock_http_init.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connection_pool_manager_initialize_all_with_error(self):
        """Тест инициализации всех пулов с ошибкой"""
        manager = ConnectionPoolManager()
        
        with patch.object(manager.database_pool, 'initialize', new_callable=AsyncMock) as mock_db_init, \
             patch.object(manager.redis_pool, 'initialize', new_callable=AsyncMock) as mock_redis_init, \
             patch.object(manager.http_pool, 'initialize', new_callable=AsyncMock) as mock_http_init:
            
            mock_db_init.side_effect = Exception("Database connection failed")
            
            with pytest.raises(Exception, match="Database connection failed"):
                await manager.initialize_all()
    
    @pytest.mark.asyncio
    async def test_connection_pool_manager_close_all(self):
        """Тест закрытия всех пулов"""
        manager = ConnectionPoolManager()
        
        with patch.object(manager.database_pool, 'close', new_callable=AsyncMock) as mock_db_close, \
             patch.object(manager.redis_pool, 'close', new_callable=AsyncMock) as mock_redis_close, \
             patch.object(manager.http_pool, 'close', new_callable=AsyncMock) as mock_http_close:
            
            await manager.close_all()
            
            mock_db_close.assert_called_once()
            mock_redis_close.assert_called_once()
            mock_http_close.assert_called_once()
    
    def test_connection_pool_manager_get_all_stats(self):
        """Тест получения статистики всех пулов"""
        manager = ConnectionPoolManager()
        
        with patch.object(manager.database_pool, 'get_stats', return_value={"type": "database", "size": 5}), \
             patch.object(manager.redis_pool, 'get_stats', return_value={"type": "redis", "clients": 3}), \
             patch.object(manager.http_pool, 'get_stats', return_value={"type": "http", "requests": 100}):
            
            stats = manager.get_all_stats()
            
            assert "database" in stats
            assert "redis" in stats
            assert "http" in stats
            assert stats["database"]["type"] == "database"
            assert stats["redis"]["type"] == "redis"
            assert stats["http"]["type"] == "http"
    
    @pytest.mark.asyncio
    async def test_connection_pool_manager_health_check(self):
        """Тест проверки здоровья всех пулов"""
        manager = ConnectionPoolManager()
        
        # Настраиваем моки для здоровых пулов
        with patch.object(manager.database_pool, 'execute', new_callable=AsyncMock, return_value="OK"), \
             patch.object(manager.redis_pool, 'get', new_callable=AsyncMock, return_value="OK"), \
             patch.object(manager.http_pool, 'get', new_callable=AsyncMock) as mock_http_get:
            
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_http_get.return_value = mock_response
            
            health = await manager.health_check()
            
            assert health["database"]["status"] == "healthy"
            assert health["redis"]["status"] == "healthy"
            assert health["http"]["status"] == "healthy"
            assert health["overall_status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_connection_pool_manager_health_check_unhealthy(self):
        """Тест проверки здоровья с нездоровыми пулами"""
        manager = ConnectionPoolManager()
        
        # Настраиваем моки для нездоровых пулов
        with patch.object(manager.database_pool, 'execute', new_callable=AsyncMock, side_effect=Exception("DB Error")), \
             patch.object(manager.redis_pool, 'get', new_callable=AsyncMock, return_value="OK"), \
             patch.object(manager.http_pool, 'get', new_callable=AsyncMock) as mock_http_get:
            
            mock_response = AsyncMock()
            mock_response.status_code = 500
            mock_http_get.return_value = mock_response
            
            health = await manager.health_check()
            
            assert health["database"]["status"] == "unhealthy"
            assert health["redis"]["status"] == "healthy"
            assert health["http"]["status"] == "unhealthy"
            assert health["overall_status"] == "unhealthy"


class TestConvenienceFunctions:
    """Тесты для удобных функций"""
    
    @pytest.mark.asyncio
    async def test_get_database_pool(self):
        """Тест получения экземпляра DatabaseConnectionPool"""
        with patch('backend.services.connection_pool.manager') as mock_manager:
            mock_pool = Mock()
            mock_manager.database_pool = mock_pool
            
            result = await get_database_pool()
            
            assert result == mock_pool
    
    @pytest.mark.asyncio
    async def test_get_redis_pool(self):
        """Тест получения экземпляра RedisConnectionPool"""
        with patch('backend.services.connection_pool.manager') as mock_manager:
            mock_pool = Mock()
            mock_manager.redis_pool = mock_pool
            
            result = await get_redis_pool()
            
            assert result == mock_pool
    
    @pytest.mark.asyncio
    async def test_get_http_pool(self):
        """Тест получения экземпляра HTTPConnectionPool"""
        with patch('backend.services.connection_pool.manager') as mock_manager:
            mock_pool = Mock()
            mock_manager.http_pool = mock_pool
            
            result = await get_http_pool()
            
            assert result == mock_pool
    
    @pytest.mark.asyncio
    async def test_database_connection_context_manager(self):
        """Тест контекстного менеджера для database_connection"""
        with patch('backend.services.connection_pool.manager') as mock_manager:
            mock_pool = Mock()
            mock_connection = AsyncMock()
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_manager.database_pool = mock_pool
            
            async with database_connection() as conn:
                assert conn == mock_connection
    
    @pytest.mark.asyncio
    async def test_redis_connection_context_manager(self):
        """Тест контекстного менеджера для redis_connection"""
        with patch('backend.services.connection_pool.manager') as mock_manager:
            mock_pool = Mock()
            mock_manager.redis_pool = mock_pool
            
            async with redis_connection() as conn:
                assert conn == mock_pool


class TestIntegration:
    """Интеграционные тесты"""
    
    @pytest.mark.asyncio
    async def test_full_connection_workflow(self):
        """Тест полного workflow работы с соединениями"""
        # Создаем менеджер
        manager = ConnectionPoolManager()
        
        # Инициализируем все пулы
        with patch.object(manager.database_pool, 'initialize', new_callable=AsyncMock), \
             patch.object(manager.redis_pool, 'initialize', new_callable=AsyncMock), \
             patch.object(manager.http_pool, 'initialize', new_callable=AsyncMock):
            
            await manager.initialize_all()
        
        # Проверяем статистику
        with patch.object(manager.database_pool, 'get_stats', return_value={"type": "database", "size": 5}), \
             patch.object(manager.redis_pool, 'get_stats', return_value={"type": "redis", "clients": 3}), \
             patch.object(manager.http_pool, 'get_stats', return_value={"type": "http", "requests": 100}):
            
            stats = manager.get_all_stats()
            assert len(stats) == 3
        
        # Проверяем здоровье
        with patch.object(manager.database_pool, 'execute', new_callable=AsyncMock, return_value="OK"), \
             patch.object(manager.redis_pool, 'get', new_callable=AsyncMock, return_value="OK"), \
             patch.object(manager.http_pool, 'get', new_callable=AsyncMock) as mock_http_get:
            
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_http_get.return_value = mock_response
            
            health = await manager.health_check()
            assert health["overall_status"] == "healthy"
        
        # Закрываем все пулы
        with patch.object(manager.database_pool, 'close', new_callable=AsyncMock), \
             patch.object(manager.redis_pool, 'close', new_callable=AsyncMock), \
             patch.object(manager.http_pool, 'close', new_callable=AsyncMock):
            
            await manager.close_all()
    
    @pytest.mark.asyncio
    async def test_database_operations_workflow(self):
        """Тест workflow операций с базой данных"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Мокаем пул
        mock_pool = AsyncMock()
        pool.pool = mock_pool
        
        # Тестируем различные операции
        mock_pool.execute.return_value = "INSERT 1"
        result = await pool.execute("INSERT INTO users (name) VALUES ($1)", "test")
        assert result == "INSERT 1"
        
        mock_pool.fetch.return_value = [{"id": 1, "name": "test"}]
        result = await pool.fetch("SELECT * FROM users")
        assert len(result) == 1
        assert result[0]["name"] == "test"
        
        mock_pool.fetchrow.return_value = {"id": 1, "name": "test"}
        result = await pool.fetchrow("SELECT * FROM users WHERE id = $1", 1)
        assert result["id"] == 1
        
        mock_pool.fetchval.return_value = "test"
        result = await pool.fetchval("SELECT name FROM users WHERE id = $1", 1)
        assert result == "test"
    
    @pytest.mark.asyncio
    async def test_redis_operations_workflow(self):
        """Тест workflow операций с Redis"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        # Мокаем Redis
        mock_redis = AsyncMock()
        pool.pool = mock_redis
        
        # Тестируем различные операции
        mock_redis.set.return_value = True
        result = await pool.set("key", "value", ex=3600)
        assert result is True
        
        mock_redis.get.return_value = b"value"
        result = await pool.get("key")
        assert result == "value"
        
        mock_redis.exists.return_value = 1
        result = await pool.exists("key")
        assert result is True
        
        mock_redis.delete.return_value = 1
        result = await pool.delete("key")
        assert result == 1
    
    @pytest.mark.asyncio
    async def test_http_operations_workflow(self):
        """Тест workflow HTTP операций"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        # Мокаем HTTP клиент
        mock_client = AsyncMock()
        pool.client = mock_client
        
        # Тестируем различные HTTP методы
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        
        mock_client.get.return_value = mock_response
        result = await pool.get("https://api.example.com/data")
        assert result.status_code == 200
        
        mock_client.post.return_value = mock_response
        result = await pool.post("https://api.example.com/data", json={"key": "value"})
        assert result.status_code == 200
        
        mock_client.put.return_value = mock_response
        result = await pool.put("https://api.example.com/data/1", json={"key": "value"})
        assert result.status_code == 200
        
        mock_response.status_code = 204
        mock_client.delete.return_value = mock_response
        result = await pool.delete("https://api.example.com/data/1")
        assert result.status_code == 204