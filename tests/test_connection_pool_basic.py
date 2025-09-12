"""
Basic tests for Connection Pool Manager
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock
from backend.services.connection_pool import PoolConfig, DatabaseConnectionPool, RedisConnectionPool, HTTPConnectionPool, ConnectionPoolManager


class TestPoolConfig:
    """Test PoolConfig dataclass"""
    
    def test_default_pool_config(self):
        """Test default pool configuration"""
        config = PoolConfig()
        
        assert config.min_connections == 5
        assert config.max_connections == 20
        assert config.max_overflow == 30
        assert config.connection_timeout == 30
        assert config.command_timeout == 60
        assert config.idle_timeout == 300
        assert config.max_lifetime == 3600
    
    def test_custom_pool_config(self):
        """Test custom pool configuration"""
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
    
    def test_pool_config_validation(self):
        """Test pool configuration validation"""
        config = PoolConfig(min_connections=1, max_connections=10)
        
        assert config.min_connections >= 1
        assert config.max_connections >= config.min_connections
        assert config.connection_timeout > 0
        assert config.command_timeout > 0
        assert config.idle_timeout > 0
        assert config.max_lifetime > 0


class TestDatabaseConnectionPool:
    """Test DatabaseConnectionPool class"""
    
    def test_database_pool_initialization(self):
        """Test database pool initialization"""
        config = PoolConfig(min_connections=2, max_connections=5)
        pool = DatabaseConnectionPool(config)
        
        assert pool.config == config
        assert pool.pool is None
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_database_pool_initialize_success(self):
        """Test successful database pool initialization"""
        config = PoolConfig(min_connections=2, max_connections=5)
        pool = DatabaseConnectionPool(config)
        
        # Mock asyncpg.create_pool
        mock_pool = AsyncMock()
        with pytest.Mock() as mock_create_pool:
            mock_create_pool.return_value = mock_pool
            
            await pool.initialize("postgresql://test:test@localhost/test")
            
            assert pool._initialized is True
            assert pool.pool == mock_pool
    
    @pytest.mark.asyncio
    async def test_database_pool_initialize_already_initialized(self):
        """Test database pool initialization when already initialized"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        pool._initialized = True
        
        await pool.initialize("postgresql://test:test@localhost/test")
        
        # Should not raise error and remain initialized
        assert pool._initialized is True
    
    @pytest.mark.asyncio
    async def test_database_pool_close(self):
        """Test database pool close"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Mock pool
        mock_pool = AsyncMock()
        pool.pool = mock_pool
        pool._initialized = True
        
        await pool.close()
        
        mock_pool.close.assert_called_once()
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_database_pool_close_no_pool(self):
        """Test database pool close when no pool exists"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        await pool.close()
        
        # Should not raise error
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_database_pool_acquire_success(self):
        """Test successful connection acquisition"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Mock pool and connection
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_pool.acquire.return_value = mock_connection
        pool.pool = mock_pool
        pool._initialized = True
        
        async with pool.acquire() as conn:
            assert conn == mock_connection
        
        mock_pool.acquire.assert_called_once()
        mock_pool.release.assert_called_once_with(mock_connection)
    
    @pytest.mark.asyncio
    async def test_database_pool_acquire_not_initialized(self):
        """Test connection acquisition when pool not initialized"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        with pytest.raises(RuntimeError, match="Connection pool not initialized"):
            async with pool.acquire():
                pass
    
    @pytest.mark.asyncio
    async def test_database_pool_execute(self):
        """Test database pool execute method"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Mock pool and connection
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.execute.return_value = "result"
        mock_pool.acquire.return_value = mock_connection
        pool.pool = mock_pool
        pool._initialized = True
        
        result = await pool.execute("SELECT * FROM test", "arg1", "arg2")
        
        assert result == "result"
        mock_connection.execute.assert_called_once_with("SELECT * FROM test", "arg1", "arg2")
    
    @pytest.mark.asyncio
    async def test_database_pool_fetch(self):
        """Test database pool fetch method"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Mock pool and connection
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.fetch.return_value = [{"id": 1}, {"id": 2}]
        mock_pool.acquire.return_value = mock_connection
        pool.pool = mock_pool
        pool._initialized = True
        
        result = await pool.fetch("SELECT * FROM test")
        
        assert result == [{"id": 1}, {"id": 2}]
        mock_connection.fetch.assert_called_once_with("SELECT * FROM test")
    
    @pytest.mark.asyncio
    async def test_database_pool_fetchrow(self):
        """Test database pool fetchrow method"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Mock pool and connection
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.fetchrow.return_value = {"id": 1}
        mock_pool.acquire.return_value = mock_connection
        pool.pool = mock_pool
        pool._initialized = True
        
        result = await pool.fetchrow("SELECT * FROM test WHERE id = $1", 1)
        
        assert result == {"id": 1}
        mock_connection.fetchrow.assert_called_once_with("SELECT * FROM test WHERE id = $1", 1)
    
    @pytest.mark.asyncio
    async def test_database_pool_fetchval(self):
        """Test database pool fetchval method"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Mock pool and connection
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.fetchval.return_value = "test_value"
        mock_pool.acquire.return_value = mock_connection
        pool.pool = mock_pool
        pool._initialized = True
        
        result = await pool.fetchval("SELECT value FROM test WHERE id = $1", 1)
        
        assert result == "test_value"
        mock_connection.fetchval.assert_called_once_with("SELECT value FROM test WHERE id = $1", 1)
    
    def test_database_pool_get_stats_initialized(self):
        """Test database pool stats when initialized"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        # Mock pool with stats methods
        mock_pool = Mock()
        mock_pool.get_size.return_value = 10
        mock_pool.get_min_size.return_value = 2
        mock_pool.get_max_size.return_value = 20
        mock_pool.get_idle_size.return_value = 3
        pool.pool = mock_pool
        
        stats = pool.get_stats()
        
        assert stats["status"] == "active"
        assert stats["size"] == 10
        assert stats["min_size"] == 2
        assert stats["max_size"] == 20
        assert stats["idle_connections"] == 3
        assert stats["used_connections"] == 7
    
    def test_database_pool_get_stats_not_initialized(self):
        """Test database pool stats when not initialized"""
        config = PoolConfig()
        pool = DatabaseConnectionPool(config)
        
        stats = pool.get_stats()
        
        assert stats["status"] == "not_initialized"


class TestRedisConnectionPool:
    """Test RedisConnectionPool class"""
    
    def test_redis_pool_initialization(self):
        """Test Redis pool initialization"""
        config = PoolConfig(min_connections=2, max_connections=5)
        pool = RedisConnectionPool(config)
        
        assert pool.config == config
        assert pool.pool is None
        assert pool.redis is None
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_redis_pool_initialize_success(self):
        """Test successful Redis pool initialization"""
        config = PoolConfig(min_connections=2, max_connections=5)
        pool = RedisConnectionPool(config)
        
        # Mock Redis components
        mock_pool = Mock()
        mock_redis = AsyncMock()
        
        with pytest.Mock() as mock_from_url:
            mock_from_url.return_value = mock_pool
            with pytest.Mock() as mock_redis_class:
                mock_redis_class.return_value = mock_redis
                
                await pool.initialize("redis://localhost:6379")
                
                assert pool._initialized is True
                assert pool.pool == mock_pool
                assert pool.redis == mock_redis
    
    @pytest.mark.asyncio
    async def test_redis_pool_close(self):
        """Test Redis pool close"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        # Mock Redis
        mock_redis = AsyncMock()
        pool.redis = mock_redis
        pool._initialized = True
        
        await pool.close()
        
        mock_redis.close.assert_called_once()
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_redis_pool_get(self):
        """Test Redis pool get method"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        # Mock Redis
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "test_value"
        pool.redis = mock_redis
        pool._initialized = True
        
        result = await pool.get("test_key")
        
        assert result == "test_value"
        mock_redis.get.assert_called_once_with("test_key")
    
    @pytest.mark.asyncio
    async def test_redis_pool_set(self):
        """Test Redis pool set method"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        # Mock Redis
        mock_redis = AsyncMock()
        mock_redis.set.return_value = True
        pool.redis = mock_redis
        pool._initialized = True
        
        result = await pool.set("test_key", "test_value", ex=3600)
        
        assert result is True
        mock_redis.set.assert_called_once_with("test_key", "test_value", ex=3600)
    
    @pytest.mark.asyncio
    async def test_redis_pool_delete(self):
        """Test Redis pool delete method"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        # Mock Redis
        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 1
        pool.redis = mock_redis
        pool._initialized = True
        
        result = await pool.delete("test_key")
        
        assert result == 1
        mock_redis.delete.assert_called_once_with("test_key")
    
    def test_redis_pool_get_stats_initialized(self):
        """Test Redis pool stats when initialized"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        # Mock Redis with info method
        mock_redis = Mock()
        mock_redis.info.return_value = {
            "connected_clients": 5,
            "used_memory": 1024000,
            "keyspace": {"db0": {"keys": 100}}
        }
        pool.redis = mock_redis
        pool._initialized = True
        
        stats = pool.get_stats()
        
        assert stats["status"] == "active"
        assert "connected_clients" in stats
        assert "used_memory" in stats
    
    def test_redis_pool_get_stats_not_initialized(self):
        """Test Redis pool stats when not initialized"""
        config = PoolConfig()
        pool = RedisConnectionPool(config)
        
        stats = pool.get_stats()
        
        assert stats["status"] == "not_initialized"


class TestHTTPConnectionPool:
    """Test HTTPConnectionPool class"""
    
    def test_http_pool_initialization(self):
        """Test HTTP pool initialization"""
        config = PoolConfig(max_connections=10)
        pool = HTTPConnectionPool(config)
        
        assert pool.config == config
        assert pool.client is None
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_http_pool_initialize_success(self):
        """Test successful HTTP pool initialization"""
        config = PoolConfig(max_connections=10)
        pool = HTTPConnectionPool(config)
        
        # Mock httpx.AsyncClient
        mock_client = AsyncMock()
        with pytest.Mock() as mock_client_class:
            mock_client_class.return_value = mock_client
            
            await pool.initialize()
            
            assert pool._initialized is True
            assert pool.client == mock_client
    
    @pytest.mark.asyncio
    async def test_http_pool_close(self):
        """Test HTTP pool close"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        # Mock client
        mock_client = AsyncMock()
        pool.client = mock_client
        pool._initialized = True
        
        await pool.close()
        
        mock_client.aclose.assert_called_once()
        assert pool._initialized is False
    
    @pytest.mark.asyncio
    async def test_http_pool_get(self):
        """Test HTTP pool get method"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        # Mock client and response
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_client.get.return_value = mock_response
        pool.client = mock_client
        pool._initialized = True
        
        result = await pool.get("https://api.example.com/test")
        
        assert result.status_code == 200
        assert result.json() == {"data": "test"}
        mock_client.get.assert_called_once_with("https://api.example.com/test")
    
    @pytest.mark.asyncio
    async def test_http_pool_post(self):
        """Test HTTP pool post method"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        # Mock client and response
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 123}
        mock_client.post.return_value = mock_response
        pool.client = mock_client
        pool._initialized = True
        
        result = await pool.post("https://api.example.com/test", json={"name": "test"})
        
        assert result.status_code == 201
        assert result.json() == {"id": 123}
        mock_client.post.assert_called_once_with("https://api.example.com/test", json={"name": "test"})
    
    def test_http_pool_get_stats_initialized(self):
        """Test HTTP pool stats when initialized"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        # Mock client
        mock_client = Mock()
        pool.client = mock_client
        pool._initialized = True
        
        stats = pool.get_stats()
        
        assert stats["status"] == "active"
        assert "max_connections" in stats
    
    def test_http_pool_get_stats_not_initialized(self):
        """Test HTTP pool stats when not initialized"""
        config = PoolConfig()
        pool = HTTPConnectionPool(config)
        
        stats = pool.get_stats()
        
        assert stats["status"] == "not_initialized"


class TestConnectionPoolManager:
    """Test ConnectionPoolManager class"""
    
    def test_manager_initialization(self):
        """Test connection pool manager initialization"""
        manager = ConnectionPoolManager()
        
        assert manager.pools == {}
        assert manager.configs == {}
        assert manager._initialized is False
    
    def test_manager_add_config(self):
        """Test adding pool configuration"""
        manager = ConnectionPoolManager()
        config = PoolConfig(min_connections=5, max_connections=10)
        
        manager.add_config("test_pool", config)
        
        assert "test_pool" in manager.configs
        assert manager.configs["test_pool"] == config
    
    @pytest.mark.asyncio
    async def test_manager_initialize_all_pools(self):
        """Test initializing all pools"""
        manager = ConnectionPoolManager()
        
        # Add configs
        db_config = PoolConfig(min_connections=2, max_connections=5)
        redis_config = PoolConfig(min_connections=2, max_connections=5)
        
        manager.add_config("database", db_config)
        manager.add_config("redis", redis_config)
        
        # Mock pool initialization
        with pytest.Mock() as mock_db_pool:
            with pytest.Mock() as mock_redis_pool:
                mock_db_pool.initialize = AsyncMock()
                mock_redis_pool.initialize = AsyncMock()
                
                manager.pools["database"] = mock_db_pool
                manager.pools["redis"] = mock_redis_pool
                
                await manager.initialize_all_pools({
                    "database": "postgresql://test:test@localhost/test",
                    "redis": "redis://localhost:6379"
                })
                
                mock_db_pool.initialize.assert_called_once()
                mock_redis_pool.initialize.assert_called_once()
                assert manager._initialized is True
    
    def test_manager_get_pool(self):
        """Test getting pool by name"""
        manager = ConnectionPoolManager()
        
        # Add mock pool
        mock_pool = Mock()
        manager.pools["test_pool"] = mock_pool
        
        result = manager.get_pool("test_pool")
        
        assert result == mock_pool
    
    def test_manager_get_pool_not_found(self):
        """Test getting pool that doesn't exist"""
        manager = ConnectionPoolManager()
        
        result = manager.get_pool("nonexistent_pool")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_manager_close_all_pools(self):
        """Test closing all pools"""
        manager = ConnectionPoolManager()
        
        # Add mock pools
        mock_pool1 = AsyncMock()
        mock_pool2 = AsyncMock()
        manager.pools["pool1"] = mock_pool1
        manager.pools["pool2"] = mock_pool2
        manager._initialized = True
        
        await manager.close_all_pools()
        
        mock_pool1.close.assert_called_once()
        mock_pool2.close.assert_called_once()
        assert manager._initialized is False
    
    def test_manager_get_all_stats(self):
        """Test getting stats from all pools"""
        manager = ConnectionPoolManager()
        
        # Add mock pools with get_stats method
        mock_pool1 = Mock()
        mock_pool1.get_stats.return_value = {"status": "active", "size": 5}
        mock_pool2 = Mock()
        mock_pool2.get_stats.return_value = {"status": "active", "size": 3}
        
        manager.pools["pool1"] = mock_pool1
        manager.pools["pool2"] = mock_pool2
        
        stats = manager.get_all_stats()
        
        assert "pool1" in stats
        assert "pool2" in stats
        assert stats["pool1"]["status"] == "active"
        assert stats["pool2"]["status"] == "active"


class TestConnectionPoolIntegration:
    """Test connection pool integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_full_workflow_database_pool(self):
        """Test full workflow with database pool"""
        config = PoolConfig(min_connections=2, max_connections=5)
        pool = DatabaseConnectionPool(config)
        
        # Mock successful initialization and operations
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.execute.return_value = "INSERT 1"
        mock_connection.fetch.return_value = [{"id": 1, "name": "test"}]
        mock_pool.acquire.return_value = mock_connection
        pool.pool = mock_pool
        pool._initialized = True
        
        # Test execute
        result1 = await pool.execute("INSERT INTO test VALUES ($1)", "test_value")
        assert result1 == "INSERT 1"
        
        # Test fetch
        result2 = await pool.fetch("SELECT * FROM test")
        assert result2 == [{"id": 1, "name": "test"}]
        
        # Test stats
        stats = pool.get_stats()
        assert stats["status"] == "active"
        
        # Test close
        await pool.close()
        mock_pool.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_full_workflow_redis_pool(self):
        """Test full workflow with Redis pool"""
        config = PoolConfig(min_connections=2, max_connections=5)
        pool = RedisConnectionPool(config)
        
        # Mock successful initialization and operations
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "cached_value"
        mock_redis.set.return_value = True
        mock_redis.delete.return_value = 1
        mock_redis.info.return_value = {"connected_clients": 3}
        pool.redis = mock_redis
        pool._initialized = True
        
        # Test get
        result1 = await pool.get("test_key")
        assert result1 == "cached_value"
        
        # Test set
        result2 = await pool.set("test_key", "new_value", ex=3600)
        assert result2 is True
        
        # Test delete
        result3 = await pool.delete("test_key")
        assert result3 == 1
        
        # Test stats
        stats = pool.get_stats()
        assert stats["status"] == "active"
        
        # Test close
        await pool.close()
        mock_redis.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_manager_full_workflow(self):
        """Test full workflow with connection pool manager"""
        manager = ConnectionPoolManager()
        
        # Add configurations
        db_config = PoolConfig(min_connections=2, max_connections=5)
        redis_config = PoolConfig(min_connections=2, max_connections=5)
        
        manager.add_config("database", db_config)
        manager.add_config("redis", redis_config)
        
        # Mock pools
        mock_db_pool = AsyncMock()
        mock_redis_pool = AsyncMock()
        mock_db_pool.get_stats.return_value = {"status": "active", "size": 3}
        mock_redis_pool.get_stats.return_value = {"status": "active", "size": 2}
        
        manager.pools["database"] = mock_db_pool
        manager.pools["redis"] = mock_redis_pool
        manager._initialized = True
        
        # Test get pools
        db_pool = manager.get_pool("database")
        redis_pool = manager.get_pool("redis")
        
        assert db_pool == mock_db_pool
        assert redis_pool == mock_redis_pool
        
        # Test get all stats
        all_stats = manager.get_all_stats()
        assert "database" in all_stats
        assert "redis" in all_stats
        
        # Test close all
        await manager.close_all_pools()
        mock_db_pool.close.assert_called_once()
        mock_redis_pool.close.assert_called_once()