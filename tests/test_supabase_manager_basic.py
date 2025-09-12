"""
Basic tests for Supabase Manager
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock, patch
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
    async def test_manager_initialize_success(self):
        """Test successful manager initialization"""
        config = SupabaseConfig(max_connections=5)
        manager = SupabaseConnectionManager(config)
        
        # Mock _create_clients method
        manager._create_clients = AsyncMock()
        
        await manager.initialize()
        
        manager._create_clients.assert_called_once()
        assert manager._initialized is True
    
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
    
    def test_manager_get_client_existing(self):
        """Test getting existing client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Add mock client
        mock_client = Mock()
        manager._clients["test_client"] = mock_client
        
        result = manager.get_client("test_client")
        
        assert result == mock_client
    
    def test_manager_get_client_nonexistent(self):
        """Test getting non-existent client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        result = manager.get_client("nonexistent_client")
        
        assert result is None
    
    def test_manager_get_client_anon(self):
        """Test getting anon client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Add mock anon client
        mock_anon_client = Mock()
        manager._clients["anon"] = mock_anon_client
        
        result = manager.get_client("anon")
        
        assert result == mock_anon_client
    
    def test_manager_get_client_service_role(self):
        """Test getting service_role client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Add mock service_role client
        mock_service_client = Mock()
        manager._clients["service_role"] = mock_service_client
        
        result = manager.get_client("service_role")
        
        assert result == mock_service_client
    
    @pytest.mark.asyncio
    async def test_manager_health_check_success(self):
        """Test successful health check"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Mock client with health check
        mock_client = AsyncMock()
        mock_client.table.return_value.select.return_value.execute.return_value = {"data": []}
        manager._clients["test_client"] = mock_client
        
        result = await manager.health_check("test_client")
        
        assert result is True
        assert manager._health_status["test_client"] is True
    
    @pytest.mark.asyncio
    async def test_manager_health_check_failure(self):
        """Test failed health check"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Mock client that raises exception
        mock_client = AsyncMock()
        mock_client.table.return_value.select.return_value.execute.side_effect = Exception("Connection failed")
        manager._clients["test_client"] = mock_client
        
        result = await manager.health_check("test_client")
        
        assert result is False
        assert manager._health_status["test_client"] is False
    
    @pytest.mark.asyncio
    async def test_manager_health_check_nonexistent_client(self):
        """Test health check for non-existent client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        result = await manager.health_check("nonexistent_client")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_manager_health_check_all(self):
        """Test health check for all clients"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Mock clients
        mock_client1 = AsyncMock()
        mock_client1.table.return_value.select.return_value.execute.return_value = {"data": []}
        mock_client2 = AsyncMock()
        mock_client2.table.return_value.select.return_value.execute.side_effect = Exception("Failed")
        
        manager._clients["client1"] = mock_client1
        manager._clients["client2"] = mock_client2
        
        results = await manager.health_check_all()
        
        assert results["client1"] is True
        assert results["client2"] is False
        assert len(results) == 2
    
    def test_manager_get_status(self):
        """Test getting manager status"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Set up mock data
        manager._initialized = True
        manager._clients = {"anon": Mock(), "service_role": Mock()}
        manager._health_status = {"anon": True, "service_role": False}
        
        status = manager.get_status()
        
        assert status["initialized"] is True
        assert status["total_clients"] == 2
        assert status["healthy_clients"] == 1
        assert status["unhealthy_clients"] == 1
        assert "client_status" in status
    
    def test_manager_get_status_not_initialized(self):
        """Test getting manager status when not initialized"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        status = manager.get_status()
        
        assert status["initialized"] is False
        assert status["total_clients"] == 0
        assert status["healthy_clients"] == 0
        assert status["unhealthy_clients"] == 0
    
    @pytest.mark.asyncio
    async def test_manager_execute_operation_success(self):
        """Test successful operation execution"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Mock client and operation
        mock_client = Mock()
        mock_result = {"data": [{"id": 1, "name": "test"}]}
        manager._clients["anon"] = mock_client
        
        async def mock_operation(client):
            return mock_result
        
        result = await manager.execute_operation("anon", mock_operation)
        
        assert result == mock_result
    
    @pytest.mark.asyncio
    async def test_manager_execute_operation_failure(self):
        """Test failed operation execution"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Mock client that raises exception
        mock_client = Mock()
        manager._clients["anon"] = mock_client
        
        async def mock_operation(client):
            raise Exception("Operation failed")
        
        result = await manager.execute_operation("anon", mock_operation)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_manager_execute_operation_nonexistent_client(self):
        """Test operation execution with non-existent client"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        async def mock_operation(client):
            return {"data": []}
        
        result = await manager.execute_operation("nonexistent", mock_operation)
        
        assert result is None


class TestSupabaseManagerIntegration:
    """Test Supabase manager integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_full_workflow_initialization(self):
        """Test full workflow with manager initialization"""
        config = SupabaseConfig(max_connections=5)
        manager = SupabaseConnectionManager(config)
        
        # Mock _create_clients
        manager._create_clients = AsyncMock()
        
        # Initialize
        await manager.initialize()
        assert manager._initialized is True
        
        # Check status
        status = manager.get_status()
        assert status["initialized"] is True
        
        # Close
        await manager.close()
        assert manager._initialized is False
    
    @pytest.mark.asyncio
    async def test_full_workflow_with_clients(self):
        """Test full workflow with multiple clients"""
        config = SupabaseConfig(max_connections=3)
        manager = SupabaseConnectionManager(config)
        
        # Mock clients
        mock_anon_client = AsyncMock()
        mock_service_client = AsyncMock()
        mock_anon_client.table.return_value.select.return_value.execute.return_value = {"data": []}
        mock_service_client.table.return_value.select.return_value.execute.return_value = {"data": []}
        
        manager._clients["anon"] = mock_anon_client
        manager._clients["service_role"] = mock_service_client
        manager._initialized = True
        
        # Test get clients
        anon_client = manager.get_client("anon")
        service_client = manager.get_client("service_role")
        
        assert anon_client == mock_anon_client
        assert service_client == mock_service_client
        
        # Test health checks
        anon_health = await manager.health_check("anon")
        service_health = await manager.health_check("service_role")
        
        assert anon_health is True
        assert service_health is True
        
        # Test operation execution
        async def test_operation(client):
            return {"data": "test_result"}
        
        result = await manager.execute_operation("anon", test_operation)
        assert result == {"data": "test_result"}
        
        # Test status
        status = manager.get_status()
        assert status["total_clients"] == 2
        assert status["healthy_clients"] == 2
    
    @pytest.mark.asyncio
    async def test_error_handling_scenarios(self):
        """Test error handling in various scenarios"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        # Test health check with failing client
        mock_failing_client = AsyncMock()
        mock_failing_client.table.return_value.select.return_value.execute.side_effect = Exception("Connection timeout")
        manager._clients["failing_client"] = mock_failing_client
        
        health_result = await manager.health_check("failing_client")
        assert health_result is False
        
        # Test operation with failing client
        async def failing_operation(client):
            raise Exception("Database error")
        
        operation_result = await manager.execute_operation("failing_client", failing_operation)
        assert operation_result is None
        
        # Test status with mixed health
        manager._health_status["failing_client"] = False
        status = manager.get_status()
        assert status["unhealthy_clients"] == 1
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test concurrent operations"""
        config = SupabaseConfig(max_connections=5)
        manager = SupabaseConnectionManager(config)
        
        # Mock client
        mock_client = AsyncMock()
        mock_client.table.return_value.select.return_value.execute.return_value = {"data": []}
        manager._clients["anon"] = mock_client
        manager._initialized = True
        
        # Define concurrent operation
        async def concurrent_operation():
            return await manager.health_check("anon")
        
        # Run multiple concurrent operations
        tasks = [concurrent_operation() for _ in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        assert all(results)
        assert len(results) == 5
    
    @pytest.mark.asyncio
    async def test_retry_mechanism(self):
        """Test retry mechanism in operations"""
        config = SupabaseConfig(retry_attempts=3, retry_delay=0.1)
        manager = SupabaseConnectionManager(config)
        
        # Mock client that fails first two times, then succeeds
        mock_client = AsyncMock()
        call_count = 0
        
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise Exception("Temporary failure")
            return {"data": []}
        
        mock_client.table.return_value.select.return_value.execute.side_effect = side_effect
        manager._clients["anon"] = mock_client
        
        # Health check should eventually succeed
        result = await manager.health_check("anon")
        assert result is True
        assert call_count == 3  # Should have retried 3 times


class TestSupabaseManagerEdgeCases:
    """Test Supabase manager edge cases"""
    
    def test_manager_with_zero_connections(self):
        """Test manager with zero max connections"""
        config = SupabaseConfig(max_connections=0)
        manager = SupabaseConnectionManager(config)
        
        assert manager.config.max_connections == 0
        assert manager._thread_pool is not None
    
    def test_manager_with_high_connection_count(self):
        """Test manager with high connection count"""
        config = SupabaseConfig(max_connections=100)
        manager = SupabaseConnectionManager(config)
        
        assert manager.config.max_connections == 100
        assert manager._thread_pool is not None
    
    @pytest.mark.asyncio
    async def test_manager_operation_with_none_result(self):
        """Test operation that returns None"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        mock_client = Mock()
        manager._clients["anon"] = mock_client
        
        async def none_operation(client):
            return None
        
        result = await manager.execute_operation("anon", none_operation)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_manager_operation_with_complex_result(self):
        """Test operation with complex result"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        mock_client = Mock()
        manager._clients["anon"] = mock_client
        
        complex_result = {
            "data": [
                {"id": 1, "name": "test1", "metadata": {"type": "user"}},
                {"id": 2, "name": "test2", "metadata": {"type": "admin"}}
            ],
            "count": 2,
            "status": "success"
        }
        
        async def complex_operation(client):
            return complex_result
        
        result = await manager.execute_operation("anon", complex_operation)
        assert result == complex_result
        assert result["count"] == 2
        assert len(result["data"]) == 2
    
    def test_manager_status_with_empty_clients(self):
        """Test status with empty clients dictionary"""
        config = SupabaseConfig()
        manager = SupabaseConnectionManager(config)
        
        manager._initialized = True
        manager._clients = {}
        manager._health_status = {}
        
        status = manager.get_status()
        
        assert status["total_clients"] == 0
        assert status["healthy_clients"] == 0
        assert status["unhealthy_clients"] == 0
        assert status["client_status"] == {}