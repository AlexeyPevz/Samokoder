"""
Integration tests for DI Container
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from backend.core.container import DIContainer, get_service, get_service_sync
from backend.contracts.ai_service import AIServiceProtocol

class TestAIService:
    """Test AI Service implementation"""
    
    def __init__(self):
        self.name = "test_ai_service"
    
    async def chat_completion(self, request):
        return {"response": "test response"}

class TestDIContainerIntegration:
    """Integration tests for DI Container"""
    
    def test_container_registration(self):
        """Test service registration"""
        container = DIContainer()
        
        # Register service
        container.register(AIServiceProtocol, TestAIService)
        
        # Check if registered
        assert container.is_registered(AIServiceProtocol)
    
    def test_container_factory_registration(self):
        """Test factory registration"""
        container = DIContainer()
        
        # Register factory
        container.register_factory(AIServiceProtocol, lambda: TestAIService())
        
        # Check if registered
        assert container.is_registered(AIServiceProtocol)
    
    def test_container_instance_registration(self):
        """Test instance registration"""
        container = DIContainer()
        instance = TestAIService()
        
        # Register instance
        container.register_instance(AIServiceProtocol, instance)
        
        # Check if registered
        assert container.is_registered(AIServiceProtocol)
    
    def test_sync_service_retrieval(self):
        """Test synchronous service retrieval"""
        container = DIContainer()
        container.register(AIServiceProtocol, TestAIService)
        
        # Get service
        service = container.get_sync(AIServiceProtocol)
        
        # Check type
        assert isinstance(service, TestAIService)
    
    @pytest.mark.asyncio
    async def test_async_service_retrieval(self):
        """Test asynchronous service retrieval"""
        container = DIContainer()
        container.register(AIServiceProtocol, TestAIService)
        
        # Get service
        service = await container.get(AIServiceProtocol)
        
        # Check type
        assert isinstance(service, TestAIService)
    
    @pytest.mark.asyncio
    async def test_singleton_behavior(self):
        """Test singleton behavior"""
        container = DIContainer()
        container.register(AIServiceProtocol, TestAIService, singleton=True)
        
        # Get service twice
        service1 = await container.get(AIServiceProtocol)
        service2 = await container.get(AIServiceProtocol)
        
        # Should be same instance
        assert service1 is service2
    
    @pytest.mark.asyncio
    async def test_transient_behavior(self):
        """Test transient behavior"""
        container = DIContainer()
        container.register(AIServiceProtocol, TestAIService, singleton=False)
        
        # Get service twice
        service1 = await container.get(AIServiceProtocol)
        service2 = await container.get(AIServiceProtocol)
        
        # Should be different instances
        assert service1 is not service2
    
    @pytest.mark.asyncio
    async def test_thread_safety(self):
        """Test thread safety with concurrent access"""
        container = DIContainer()
        container.register(AIServiceProtocol, TestAIService, singleton=True)
        
        # Create multiple concurrent tasks
        tasks = []
        for _ in range(10):
            task = asyncio.create_task(container.get(AIServiceProtocol))
            tasks.append(task)
        
        # Wait for all tasks
        services = await asyncio.gather(*tasks)
        
        # All should be the same instance (singleton)
        first_service = services[0]
        for service in services[1:]:
            assert service is first_service
    
    def test_global_container_functions(self):
        """Test global container functions"""
        # Register service
        from backend.core.container import container
        container.register(AIServiceProtocol, TestAIService)
        
        # Test sync function
        service = get_service_sync(AIServiceProtocol)
        assert isinstance(service, TestAIService)
    
    @pytest.mark.asyncio
    async def test_global_container_async_functions(self):
        """Test global container async functions"""
        # Register service
        from backend.core.container import container
        container.register(AIServiceProtocol, TestAIService)
        
        # Test async function
        service = await get_service(AIServiceProtocol)
        assert isinstance(service, TestAIService)
    
    def test_error_handling(self):
        """Test error handling for unregistered services"""
        container = DIContainer()
        
        # Try to get unregistered service
        with pytest.raises(ValueError):
            container.get_sync(AIServiceProtocol)
    
    @pytest.mark.asyncio
    async def test_optional_service_retrieval(self):
        """Test optional service retrieval"""
        container = DIContainer()
        
        # Test unregistered service
        service = await container.get_optional(AIServiceProtocol)
        assert service is None
        
        # Register and test
        container.register(AIServiceProtocol, TestAIService)
        service = await container.get_optional(AIServiceProtocol)
        assert isinstance(service, TestAIService)