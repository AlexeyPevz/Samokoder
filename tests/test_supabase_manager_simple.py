"""
Simple tests for Supabase Manager - focusing on basic functionality
"""
import pytest
from unittest.mock import Mock, AsyncMock
from backend.services.supabase_manager import SupabaseConfig, SupabaseConnectionManager


class TestSupabaseConfig:
    """Test SupabaseConfig dataclass"""
    
    def test_default_supabase_config(self):
        """Test default Supabase configuration"""
        config = SupabaseConfig()
        
        assert config.max_connections == 10
        assert config.connection_timeout == 30
        assert config.retry_attempts == 3
        assert config.retry_delay == 1.0
        assert config.health_check_interval == 60
    
    def test_custom_supabase_config(self):
        """Test custom Supabase configuration"""
        config = SupabaseConfig(
            max_connections=20,
            connection_timeout=60,
            retry_attempts=5,
            retry_delay=2.0,
            health_check_interval=120
        )
        
        assert config.max_connections == 20
        assert config.connection_timeout == 60
        assert config.retry_attempts == 5
        assert config.retry_delay == 2.0
        assert config.health_check_interval == 120
    
    def test_supabase_config_validation(self):
        """Test Supabase configuration validation"""
        config = SupabaseConfig(
            max_connections=1,
            connection_timeout=1,
            retry_attempts=1,
            retry_delay=0.1
        )
        
        assert config.max_connections >= 1
        assert config.connection_timeout > 0
        assert config.retry_attempts >= 1
        assert config.retry_delay > 0
        assert config.health_check_interval > 0


class TestSupabaseConnectionManager:
    """Test SupabaseConnectionManager class"""
    
    def test_manager_initialization(self):
        """Test Supabase connection manager initialization"""
        config = SupabaseConfig(max_connections=5)
        manager = SupabaseConnectionManager(config)
        
        assert manager.config == config
        assert manager._clients == {}
        assert manager._health_status == {}
        assert manager._last_health_check == {}
        assert manager._initialized is False
        assert manager._thread_pool is not None
    
    def test_manager_initialization_default_config(self):
        """Test Supabase connection manager initialization with default config"""
        manager = SupabaseConnectionManager()
        
        assert isinstance(manager.config, SupabaseConfig)
        assert manager.config.max_connections == 10
        assert manager._initialized is False
    
    @pytest.mark.asyncio
    async def test_manager_initialize_already_initialized(self):
        """Test manager initialization when already initialized"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        manager._initialized = True
        
        # Mock _create_clients method
        manager._create_clients = AsyncMock()
        
        await manager.initialize()
        
        # Should not call _create_clients again
        manager._create_clients.assert_not_called()
        assert manager._initialized is True
    
    @pytest.mark.asyncio
    async def test_manager_close(self):
        """Test manager close"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Mock thread pool
        mock_thread_pool = Mock()
        mock_thread_pool.shutdown.return_value = None
        manager._thread_pool = mock_thread_pool
        manager._initialized = True
        
        await manager.close()
        
        mock_thread_pool.shutdown.assert_called_once()
        assert manager._initialized is False
    
    @pytest.mark.asyncio
    async def test_manager_close_not_initialized(self):
        """Test manager close when not initialized"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        await manager.close()
        
        # Should not raise error
        assert manager._initialized is False
    
    def test_manager_get_client_not_initialized(self):
        """Test getting client when manager not initialized"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        result = manager.get_client("anon")
        
        assert result is None
    
    def test_manager_get_client_nonexistent(self):
        """Test getting non-existent client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        manager._initialized = True
        
        result = manager.get_client("nonexistent_client")
        
        assert result is None
    
    def test_manager_get_client_unhealthy(self):
        """Test getting unhealthy client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        manager._initialized = True
        
        # Add unhealthy client
        mock_client = Mock()
        manager._clients["unhealthy_client"] = mock_client
        manager._health_status["unhealthy_client"] = False
        
        # Mock _is_client_healthy to return False
        manager._is_client_healthy = Mock(return_value=False)
        
        result = manager.get_client("unhealthy_client")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_manager_health_check_all(self):
        """Test health check for all clients"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Mock clients
        mock_client1 = Mock()
        mock_client2 = Mock()
        manager._clients["client1"] = mock_client1
        manager._clients["client2"] = mock_client2
        manager._initialized = True
        
        # Mock _is_client_healthy method
        manager._is_client_healthy = Mock(side_effect=lambda x: x == "client1")
        
        results = await manager.health_check_all()
        
        assert "client1" in results
        assert "client2" in results
        assert len(results) == 2
    
    @pytest.mark.asyncio
    async def test_manager_execute_async_not_initialized(self):
        """Test async execution when manager not initialized"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        async def mock_operation():
            return "result"
        
        with pytest.raises(RuntimeError, match="Supabase anon client not available"):
            await manager.execute_async(mock_operation, "anon")
    
    @pytest.mark.asyncio
    async def test_manager_execute_async_no_client(self):
        """Test async execution when no client available"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        manager._initialized = True
        
        async def mock_operation():
            return "result"
        
        with pytest.raises(RuntimeError, match="Supabase nonexistent client not available"):
            await manager.execute_async(mock_operation, "nonexistent")
    
    def test_manager_is_client_healthy_not_checked(self):
        """Test client health check for unregistered client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        result = manager._is_client_healthy("unregistered_client")
        
        assert result is False
    
    def test_manager_is_client_healthy_no_client(self):
        """Test client health check when no client exists"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Add client to health status but not to clients
        manager._health_status["missing_client"] = True
        
        result = manager._is_client_healthy("missing_client")
        
        assert result is False


class TestSupabaseManagerIntegration:
    """Test Supabase manager integration scenarios"""
    
    def test_manager_thread_pool_configuration(self):
        """Test thread pool configuration"""
        config = SupabaseConfig(max_connections=5)
        manager = SupabaseConnectionManager(config)
        
        assert manager._thread_pool is not None
        assert manager._thread_pool._max_workers == 5
    
    def test_manager_health_status_management(self):
        """Test health status management"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Initially empty
        assert manager._health_status == {}
        
        # Add health status
        manager._health_status["test_client"] = True
        assert manager._health_status["test_client"] is True
        
        # Update health status
        manager._health_status["test_client"] = False
        assert manager._health_status["test_client"] is False
    
    def test_manager_last_health_check_management(self):
        """Test last health check timestamp management"""
        from datetime import datetime
        
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Initially empty
        assert manager._last_health_check == {}
        
        # Add timestamp
        now = datetime.now()
        manager._last_health_check["test_client"] = now
        assert manager._last_health_check["test_client"] == now
    
    def test_manager_clients_management(self):
        """Test clients management"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Initially empty
        assert manager._clients == {}
        
        # Add client
        mock_client = Mock()
        manager._clients["test_client"] = mock_client
        assert manager._clients["test_client"] == mock_client
        
        # Remove client
        del manager._clients["test_client"]
        assert "test_client" not in manager._clients
    
    def test_manager_initialization_state(self):
        """Test initialization state management"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Initially not initialized
        assert manager._initialized is False
        
        # Set initialized
        manager._initialized = True
        assert manager._initialized is True
        
        # Reset
        manager._initialized = False
        assert manager._initialized is False


class TestSupabaseManagerEdgeCases:
    """Test Supabase manager edge cases"""
    
    def test_manager_with_minimum_connections(self):
        """Test manager with minimum connections"""
        config = SupabaseConfig(max_connections=1)
        manager = SupabaseConnectionManager(config)
        
        assert manager.config.max_connections == 1
        assert manager._thread_pool._max_workers == 1
    
    def test_manager_with_high_connection_count(self):
        """Test manager with high connection count"""
        config = SupabaseConfig(max_connections=100)
        manager = SupabaseConnectionManager(config)
        
        assert manager.config.max_connections == 100
        assert manager._thread_pool._max_workers == 100
    
    def test_manager_config_immutability(self):
        """Test manager config immutability"""
        config = SupabaseConfig(max_connections=5)
        manager = SupabaseConnectionManager(config)
        
        original_max_connections = manager.config.max_connections
        
        # Config is mutable in dataclass, so this will change
        manager.config.max_connections = 10
        
        # Should be modified value (dataclass is mutable)
        assert manager.config.max_connections == 10
    
    @pytest.mark.asyncio
    async def test_manager_empty_clients_dict(self):
        """Test manager with empty clients dictionary"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        manager._initialized = True
        manager._clients = {}
        
        # Should handle empty clients gracefully
        result = manager.get_client("any_client")
        assert result is None
        
        health_results = await manager.health_check_all()
        assert health_results == {}
    
    def test_manager_health_status_edge_cases(self):
        """Test health status edge cases"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Test with None values
        manager._health_status["client1"] = None
        assert manager._health_status["client1"] is None
        
        # Test with mixed types
        manager._health_status["client2"] = "healthy"
        assert manager._health_status["client2"] == "healthy"
        
        # Test with boolean False
        manager._health_status["client3"] = False
        assert manager._health_status["client3"] is False
    
    def test_manager_thread_pool_edge_cases(self):
        """Test thread pool edge cases"""
        # Test with zero connections (should fail)
        with pytest.raises(ValueError, match="max_workers must be greater than 0"):
            config = SupabaseConfig(max_connections=0)
            SupabaseConnectionManager(config)
    
    def test_manager_initialization_consistency(self):
        """Test initialization consistency"""
        config = SupabaseConfig()
        manager1 = SupabaseConnectionManager(config)
        manager2 = SupabaseConnectionManager(config)
        
        # Both should have same initial state
        assert manager1._initialized == manager2._initialized
        assert manager1._clients == manager2._clients
        assert manager1._health_status == manager2._health_status
        assert manager1._last_health_check == manager2._last_health_check
    
    def test_manager_config_defaults(self):
        """Test manager config defaults"""
        manager = SupabaseConnectionManager()
        
        # Should use default config values
        assert manager.config.max_connections == 10
        assert manager.config.connection_timeout == 30
        assert manager.config.retry_attempts == 3
        assert manager.config.retry_delay == 1.0
        assert manager.config.health_check_interval == 60