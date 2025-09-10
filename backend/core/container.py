"""
Dependency Injection Container
"""
from typing import Type, TypeVar, Dict, Any, Optional, Callable
import logging
import asyncio
from functools import lru_cache

logger = logging.getLogger(__name__)

T = TypeVar('T')

class DIContainer:
    """Dependency Injection Container with thread safety"""
    
    def __init__(self):
        self._services: Dict[Type, Type] = {}
        self._instances: Dict[Type, Any] = {}
        self._factories: Dict[Type, Callable] = {}
        self._singletons: Dict[Type, bool] = {}
        self._lock = asyncio.Lock()
    
    def register(self, interface: Type[T], implementation: Type[T], singleton: bool = True) -> None:
        """Register a service implementation"""
        self._services[interface] = implementation
        self._singletons[interface] = singleton
        logger.debug(f"Registered {interface.__name__} -> {implementation.__name__} (singleton: {singleton})")
    
    def register_factory(self, interface: Type[T], factory: Callable[[], T], singleton: bool = True) -> None:
        """Register a factory function for a service"""
        self._factories[interface] = factory
        self._singletons[interface] = singleton
        logger.debug(f"Registered factory for {interface.__name__} (singleton: {singleton})")
    
    def register_instance(self, interface: Type[T], instance: T) -> None:
        """Register a service instance"""
        self._instances[interface] = instance
        self._singletons[interface] = True
        logger.debug(f"Registered instance for {interface.__name__}")
    
    async def get(self, interface: Type[T]) -> T:
        """Get a service instance with thread safety"""
        # Check if we have a registered instance (fast path)
        if interface in self._instances:
            return self._instances[interface]
        
        # Use lock for singleton creation
        async with self._lock:
            # Double-check pattern for singleton creation
            if interface in self._instances:
                return self._instances[interface]
            
            # Check if we have a factory
            if interface in self._factories:
                if self._singletons.get(interface, True):
                    if interface not in self._instances:
                        self._instances[interface] = self._factories[interface]()
                    return self._instances[interface]
                else:
                    return self._factories[interface]()
            
            # Check if we have a registered implementation
            if interface in self._services:
                implementation = self._services[interface]
                if self._singletons.get(interface, True):
                    if interface not in self._instances:
                        self._instances[interface] = implementation()
                    return self._instances[interface]
                else:
                    return implementation()
            
            raise ValueError(f"No registration found for {interface.__name__}")
    
    def get_sync(self, interface: Type[T]) -> T:
        """Get a service instance synchronously (for non-async contexts)"""
        # Check if we have a registered instance
        if interface in self._instances:
            return self._instances[interface]
        
        # Check if we have a factory
        if interface in self._factories:
            if self._singletons.get(interface, True):
                if interface not in self._instances:
                    self._instances[interface] = self._factories[interface]()
                return self._instances[interface]
            else:
                return self._factories[interface]()
        
        # Check if we have a registered implementation
        if interface in self._services:
            implementation = self._services[interface]
            if self._singletons.get(interface, True):
                if interface not in self._instances:
                    self._instances[interface] = implementation()
                return self._instances[interface]
            else:
                return implementation()
        
        raise ValueError(f"No registration found for {interface.__name__}")
    
    async def get_optional(self, interface: Type[T]) -> Optional[T]:
        """Get a service instance or None if not registered"""
        try:
            return await self.get(interface)
        except ValueError:
            return None
    
    def get_optional_sync(self, interface: Type[T]) -> Optional[T]:
        """Get a service instance or None if not registered (sync version)"""
        try:
            return self.get_sync(interface)
        except ValueError:
            return None
    
    def is_registered(self, interface: Type[T]) -> bool:
        """Check if a service is registered"""
        return interface in self._services or interface in self._factories or interface in self._instances
    
    def clear(self) -> None:
        """Clear all registrations"""
        self._services.clear()
        self._instances.clear()
        self._factories.clear()
        self._singletons.clear()
        logger.debug("Cleared all service registrations")
    
    def get_registered_services(self) -> Dict[str, str]:
        """Get list of registered services"""
        services = {}
        
        for interface in self._services:
            services[interface.__name__] = f"Implementation: {self._services[interface].__name__}"
        
        for interface in self._factories:
            services[interface.__name__] = f"Factory: {self._factories[interface].__name__}"
        
        for interface in self._instances:
            services[interface.__name__] = f"Instance: {type(self._instances[interface]).__name__}"
        
        return services

# Глобальный контейнер
container = DIContainer()

async def get_service(interface: Type[T]) -> T:
    """Get a service from the global container"""
    return await container.get(interface)

def get_service_sync(interface: Type[T]) -> T:
    """Get a service from the global container (sync version)"""
    return container.get_sync(interface)

async def get_optional_service(interface: Type[T]) -> Optional[T]:
    """Get an optional service from the global container"""
    return await container.get_optional(interface)

def get_optional_service_sync(interface: Type[T]) -> Optional[T]:
    """Get an optional service from the global container (sync version)"""
    return container.get_optional_sync(interface)

@lru_cache(maxsize=128)
def cached_get_service_sync(interface: Type[T]) -> T:
    """Cached version of get_service for better performance (sync version)"""
    return container.get_sync(interface)