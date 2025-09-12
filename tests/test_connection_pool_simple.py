"""
Упрощенные тесты для Connection Pool (27% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio
from datetime import datetime, timedelta

from backend.services.connection_pool import (
    PoolConfig,
    DatabaseConnectionPool,
    RedisConnectionPool,
    HTTPConnectionPool,
    ConnectionPoolManager
)


class TestPoolConfig:
    """Тесты для PoolConfig"""

    def test_init_default(self):
        """Тест инициализации с параметрами по умолчанию"""
        config = PoolConfig()
        
        assert config.min_connections == 5
        assert config.max_connections == 20
        assert config.max_overflow == 30
        assert config.connection_timeout == 30
        assert config.command_timeout == 60
        assert config.idle_timeout == 300
        assert config.max_lifetime == 3600

    def test_init_custom(self):
        """Тест инициализации с кастомными параметрами"""
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

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.config = PoolConfig()
        self.pool = DatabaseConnectionPool(self.config)

    def test_init(self):
        """Тест инициализации"""
        assert self.pool.config == self.config
        assert self.pool.pool is None
        assert self.pool._initialized is False

    @pytest.mark.asyncio
    @patch('backend.services.connection_pool.asyncpg.create_pool')
    async def test_initialize_success(self, mock_create_pool):
        """Тест успешной инициализации"""
        # Arrange
        mock_pool = AsyncMock()
        mock_create_pool.return_value = mock_pool
        database_url = "postgresql://test:test@localhost/test"
        
        # Act
        await self.pool.initialize(database_url)
        
        # Assert
        assert self.pool._initialized is True
        assert self.pool.pool == mock_pool
        mock_create_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_already_initialized(self):
        """Тест инициализации уже инициализированного пула"""
        # Arrange
        self.pool._initialized = True
        
        # Act
        await self.pool.initialize("postgresql://test:test@localhost/test")
        
        # Assert
        assert self.pool._initialized is True

    @pytest.mark.asyncio
    async def test_close_not_initialized(self):
        """Тест закрытия неинициализированного пула"""
        # Act
        await self.pool.close()
        
        # Assert
        assert self.pool._initialized is False

    @pytest.mark.asyncio
    async def test_close_initialized(self):
        """Тест закрытия инициализированного пула"""
        # Arrange
        mock_pool = AsyncMock()
        self.pool.pool = mock_pool
        self.pool._initialized = True
        
        # Act
        await self.pool.close()
        
        # Assert
        mock_pool.close.assert_called_once()
        assert self.pool._initialized is False

    @pytest.mark.asyncio
    async def test_execute_not_initialized(self):
        """Тест выполнения запроса без инициализации"""
        # Act & Assert
        with pytest.raises(Exception):
            await self.pool.execute("SELECT 1")

    @pytest.mark.asyncio
    async def test_execute_initialized(self):
        """Тест выполнения запроса"""
        # Arrange
        mock_pool = AsyncMock()
        mock_pool.fetch.return_value = [{"id": 1, "name": "test"}]
        self.pool.pool = mock_pool
        self.pool._initialized = True
        
        # Act
        result = await self.pool.execute("SELECT * FROM users")
        
        # Assert
        assert result == [{"id": 1, "name": "test"}]
        mock_pool.fetch.assert_called_once_with("SELECT * FROM users")

    @pytest.mark.asyncio
    async def test_is_healthy_true(self):
        """Тест проверки здоровья пула - здоров"""
        # Arrange
        mock_pool = AsyncMock()
        mock_pool.fetch.return_value = [{"result": 1}]
        self.pool.pool = mock_pool
        self.pool._initialized = True
        
        # Act
        result = await self.pool.is_healthy()
        
        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_is_healthy_false(self):
        """Тест проверки здоровья пула - нездоров"""
        # Arrange
        mock_pool = AsyncMock()
        mock_pool.fetch.side_effect = Exception("Connection failed")
        self.pool.pool = mock_pool
        self.pool._initialized = True
        
        # Act
        result = await self.pool.is_healthy()
        
        # Assert
        assert result is False


class TestRedisConnectionPool:
    """Тесты для RedisConnectionPool"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.config = PoolConfig()
        self.pool = RedisConnectionPool(self.config)

    def test_init(self):
        """Тест инициализации"""
        assert self.pool.config == self.config
        assert self.pool.pool is None
        assert self.pool._initialized is False

    @pytest.mark.asyncio
    @patch('backend.services.connection_pool.aioredis.from_url')
    async def test_initialize_success(self, mock_from_url):
        """Тест успешной инициализации"""
        # Arrange
        mock_pool = AsyncMock()
        mock_from_url.return_value = mock_pool
        redis_url = "redis://localhost:6379"
        
        # Act
        await self.pool.initialize(redis_url)
        
        # Assert
        assert self.pool._initialized is True
        assert self.pool.pool == mock_pool
        mock_from_url.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_not_initialized(self):
        """Тест получения значения без инициализации"""
        # Act & Assert
        with pytest.raises(Exception):
            await self.pool.get("key")

    @pytest.mark.asyncio
    async def test_get_initialized(self):
        """Тест получения значения"""
        # Arrange
        mock_pool = AsyncMock()
        mock_pool.get.return_value = b"test_value"
        self.pool.pool = mock_pool
        self.pool._initialized = True
        
        # Act
        result = await self.pool.get("test_key")
        
        # Assert
        assert result == b"test_value"
        mock_pool.get.assert_called_once_with("test_key")

    @pytest.mark.asyncio
    async def test_set_not_initialized(self):
        """Тест установки значения без инициализации"""
        # Act & Assert
        with pytest.raises(Exception):
            await self.pool.set("key", "value")

    @pytest.mark.asyncio
    async def test_set_initialized(self):
        """Тест установки значения"""
        # Arrange
        mock_pool = AsyncMock()
        mock_pool.set.return_value = True
        self.pool.pool = mock_pool
        self.pool._initialized = True
        
        # Act
        result = await self.pool.set("test_key", "test_value")
        
        # Assert
        assert result is True
        mock_pool.set.assert_called_once_with("test_key", "test_value")


class TestHTTPConnectionPool:
    """Тесты для HTTPConnectionPool"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.config = PoolConfig()
        self.pool = HTTPConnectionPool(self.config)

    def test_init(self):
        """Тест инициализации"""
        assert self.pool.config == self.config
        assert self.pool.client is None
        assert self.pool._initialized is False

    @pytest.mark.asyncio
    async def test_initialize_success(self):
        """Тест успешной инициализации"""
        # Act
        await self.pool.initialize()
        
        # Assert
        assert self.pool._initialized is True
        assert self.pool.client is not None

    @pytest.mark.asyncio
    async def test_get_not_initialized(self):
        """Тест GET запроса без инициализации"""
        # Act & Assert
        with pytest.raises(Exception):
            await self.pool.get("/test")

    @pytest.mark.asyncio
    async def test_get_initialized(self):
        """Тест GET запроса"""
        # Arrange
        await self.pool.initialize()
        mock_response = Mock()
        mock_response.json.return_value = {"status": "success"}
        self.pool.client.get.return_value = mock_response
        
        # Act
        result = await self.pool.get("/test")
        
        # Assert
        assert result == mock_response
        self.pool.client.get.assert_called_once_with("/test")

    @pytest.mark.asyncio
    async def test_post_not_initialized(self):
        """Тест POST запроса без инициализации"""
        # Act & Assert
        with pytest.raises(Exception):
            await self.pool.post("/test", {"data": "test"})

    @pytest.mark.asyncio
    async def test_post_initialized(self):
        """Тест POST запроса"""
        # Arrange
        await self.pool.initialize()
        mock_response = Mock()
        mock_response.json.return_value = {"id": 1}
        self.pool.client.post.return_value = mock_response
        
        # Act
        result = await self.pool.post("/test", json={"data": "test"})
        
        # Assert
        assert result == mock_response
        self.pool.client.post.assert_called_once_with("/test", json={"data": "test"})


class TestConnectionPoolManager:
    """Тесты для ConnectionPoolManager"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.manager = ConnectionPoolManager()

    def test_init(self):
        """Тест инициализации"""
        assert self.manager.database_pool is not None
        assert self.manager.redis_pool is not None
        assert self.manager.http_pool is not None
        assert self.manager._initialized is False

    @pytest.mark.asyncio
    async def test_initialize_all(self):
        """Тест инициализации всех пулов"""
        # Arrange
        with patch('backend.services.connection_pool.settings') as mock_settings:
            mock_settings.database_url = "postgresql://test:test@localhost/test"
            mock_settings.redis_url = "redis://localhost:6379"
            mock_settings.database_pool_size = 5
            mock_settings.database_max_overflow = 10
            
            with patch('backend.services.connection_pool.asyncpg.create_pool') as mock_db, \
                 patch('backend.services.connection_pool.aioredis.from_url') as mock_redis:
                
                mock_db.return_value = AsyncMock()
                mock_redis.return_value = AsyncMock()
                
                # Act
                await self.manager.initialize_all()
                
                # Assert
                assert self.manager._initialized is True

    @pytest.mark.asyncio
    async def test_close_all(self):
        """Тест закрытия всех пулов"""
        # Arrange
        self.manager.database_pool.close = AsyncMock()
        self.manager.redis_pool.close = AsyncMock()
        self.manager.http_pool.close = AsyncMock()
        
        # Act
        await self.manager.close_all()
        
        # Assert
        self.manager.database_pool.close.assert_called_once()
        self.manager.redis_pool.close.assert_called_once()
        self.manager.http_pool.close.assert_called_once()
        assert self.manager._initialized is False

    @pytest.mark.asyncio
    async def test_get_pool_status(self):
        """Тест получения статуса пулов"""
        # Arrange
        self.manager.database_pool.is_healthy = AsyncMock(return_value=True)
        self.manager.redis_pool.is_healthy = AsyncMock(return_value=False)
        self.manager.http_pool.is_healthy = AsyncMock(return_value=True)
        
        # Act
        status = await self.manager.health_check()
        
        # Assert
        assert status["pools"]["database"] is True
        assert status["pools"]["redis"] is False
        assert status["pools"]["http"] is True

    @pytest.mark.asyncio
    async def test_get_pool_status_not_initialized(self):
        """Тест получения статуса неинициализированных пулов"""
        # Act
        status = await self.manager.health_check()
        
        # Assert
        assert status["pools"]["database"] is False
        assert status["pools"]["redis"] is False
        assert status["pools"]["http"] is False