"""
Настоящий Dependency Injection контейнер
"""

import asyncio
import logging
from typing import Dict, Any, Type, TypeVar, Callable, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

T = TypeVar('T')

class DIContainer:
    """Контейнер для Dependency Injection"""
    
    def __init__(self):
        self._services: Dict[Type, Any] = {}
        self._factories: Dict[Type, Callable] = {}
        self._singletons: Dict[Type, Any] = {}
        self._initialized = False
    
    def register_singleton(self, interface: Type[T], implementation: Type[T]):
        """Зарегистрировать singleton"""
        self._services[interface] = implementation
        logger.debug(f"Registered singleton: {interface.__name__} -> {implementation.__name__}")
    
    def register_factory(self, interface: Type[T], factory: Callable[[], T]):
        """Зарегистрировать factory"""
        self._factories[interface] = factory
        logger.debug(f"Registered factory: {interface.__name__}")
    
    def register_instance(self, interface: Type[T], instance: T):
        """Зарегистрировать готовый экземпляр"""
        self._singletons[interface] = instance
        logger.debug(f"Registered instance: {interface.__name__}")
    
    def get(self, interface: Type[T]) -> T:
        """Получить сервис"""
        # Проверяем готовые экземпляры
        if interface in self._singletons:
            return self._singletons[interface]
        
        # Проверяем фабрики
        if interface in self._factories:
            instance = self._factories[interface]()
            self._singletons[interface] = instance
            return instance
        
        # Проверяем классы
        if interface in self._services:
            implementation = self._services[interface]
            instance = implementation()
            self._singletons[interface] = instance
            return instance
        
        raise ValueError(f"Service {interface.__name__} not registered")
    
    def get_optional(self, interface: Type[T]) -> Optional[T]:
        """Получить сервис (может быть None)"""
        try:
            return self.get(interface)
        except ValueError:
            return None
    
    def is_registered(self, interface: Type[T]) -> bool:
        """Проверить, зарегистрирован ли сервис"""
        return (interface in self._services or 
                interface in self._factories or 
                interface in self._singletons)
    
    def clear(self):
        """Очистить контейнер"""
        self._services.clear()
        self._factories.clear()
        self._singletons.clear()
        self._initialized = False
        logger.info("DI container cleared")
    
    def get_registered_services(self) -> Dict[str, str]:
        """Получить список зарегистрированных сервисов"""
        services = {}
        
        for interface in self._services:
            services[interface.__name__] = f"singleton -> {self._services[interface].__name__}"
        
        for interface in self._factories:
            services[interface.__name__] = "factory"
        
        for interface in self._singletons:
            services[interface.__name__] = "instance"
        
        return services

# Глобальный контейнер
_container: Optional[DIContainer] = None

def get_container() -> DIContainer:
    """Получить глобальный DI контейнер"""
    global _container
    if _container is None:
        _container = DIContainer()
        _setup_default_services()
    return _container

def _setup_default_services():
    """Настройка сервисов по умолчанию"""
    container = get_container()
    
    # Регистрируем основные сервисы
    try:
        from backend.services.rbac_service import RBACService
        from backend.services.mfa_service import MFAService
        from backend.services.ai.ai_service import AIService
        from backend.monitoring.advanced_monitoring import AdvancedMonitoring
        from backend.monitoring.enhanced_monitoring import EnhancedMonitoring
        from backend.controllers.project_controller import ProjectController
        from backend.controllers.ai_controller import AIController
        from backend.builders.project_builder import ProjectBuilder
        from backend.bus.event_bus import EventBus
        from backend.bus.command_bus import CommandBus
        
        # Регистрируем как singleton
        container.register_singleton(RBACService, RBACService)
        container.register_singleton(MFAService, MFAService)
        container.register_singleton(AIService, AIService)
        container.register_singleton(AdvancedMonitoring, AdvancedMonitoring)
        container.register_singleton(EnhancedMonitoring, EnhancedMonitoring)
        container.register_singleton(ProjectController, ProjectController)
        container.register_singleton(AIController, AIController)
        container.register_singleton(ProjectBuilder, ProjectBuilder)
        container.register_singleton(EventBus, EventBus)
        container.register_singleton(CommandBus, CommandBus)
        
        logger.info("Default services registered in DI container")
        
    except ImportError as e:
        logger.warning(f"Could not register some default services: {e}")

# Декораторы для инъекции зависимостей
def inject(interface: Type[T]):
    """Декоратор для инъекции зависимостей"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            container = get_container()
            service = container.get(interface)
            return func(service, *args, **kwargs)
        return wrapper
    return decorator

def inject_optional(interface: Type[T]):
    """Декоратор для опциональной инъекции зависимостей"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            container = get_container()
            service = container.get_optional(interface)
            return func(service, *args, **kwargs)
        return wrapper
    return decorator

# Функции для получения сервисов
@lru_cache()
def get_rbac_service():
    """Получить RBAC сервис"""
    container = get_container()
    return container.get(RBACService)

@lru_cache()
def get_mfa_service():
    """Получить MFA сервис"""
    container = get_container()
    return container.get(MFAService)

@lru_cache()
def get_ai_service():
    """Получить AI сервис"""
    container = get_container()
    return container.get(AIService)

@lru_cache()
def get_monitoring_service():
    """Получить сервис мониторинга"""
    container = get_container()
    return container.get(AdvancedMonitoring)

@lru_cache()
def get_enhanced_monitoring_service():
    """Получить улучшенный сервис мониторинга"""
    container = get_container()
    return container.get(EnhancedMonitoring)