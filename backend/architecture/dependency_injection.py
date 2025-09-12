"""
Dependency Injection Container
Контейнер для управления зависимостями
"""

import logging
from typing import Dict, Any, Type, Optional, Callable
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class DIContainer:
    """Контейнер для управления зависимостями"""
    
    def __init__(self):
        self._services: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}
        self._singletons: Dict[str, bool] = {}
        self._dependencies: Dict[str, List[str]] = {}
    
    def register_singleton(self, interface: Type, implementation: Type, name: Optional[str] = None):
        """Зарегистрировать singleton сервис"""
        service_name = name or interface.__name__
        self._services[service_name] = implementation
        self._singletons[service_name] = True
        logger.info(f"Registered singleton: {service_name}")
    
    def register_transient(self, interface: Type, implementation: Type, name: Optional[str] = None):
        """Зарегистрировать transient сервис"""
        service_name = name or interface.__name__
        self._services[service_name] = implementation
        self._singletons[service_name] = False
        logger.info(f"Registered transient: {service_name}")
    
    def register_factory(self, interface: Type, factory: Callable, name: Optional[str] = None):
        """Зарегистрировать фабрику сервиса"""
        service_name = name or interface.__name__
        self._factories[service_name] = factory
        logger.info(f"Registered factory: {service_name}")
    
    def register_instance(self, interface: Type, instance: Any, name: Optional[str] = None):
        """Зарегистрировать готовый экземпляр"""
        service_name = name or interface.__name__
        self._services[service_name] = instance
        self._singletons[service_name] = True
        logger.info(f"Registered instance: {service_name}")
    
    def get(self, interface: Type, name: Optional[str] = None) -> Any:
        """Получить сервис"""
        service_name = name or interface.__name__
        
        # Если это singleton и уже создан, возвращаем существующий
        if service_name in self._singletons and self._singletons[service_name]:
            if service_name in self._services and not callable(self._services[service_name]):
                return self._services[service_name]
        
        # Создаем новый экземпляр
        if service_name in self._factories:
            instance = self._factories[service_name]()
        elif service_name in self._services:
            service_class = self._services[service_name]
            if callable(service_class):
                instance = service_class()
            else:
                instance = service_class
        else:
            raise ValueError(f"Service not registered: {service_name}")
        
        # Если это singleton, сохраняем экземпляр
        if service_name in self._singletons and self._singletons[service_name]:
            self._services[service_name] = instance
        
        return instance
    
    def get_optional(self, interface: Type, name: Optional[str] = None) -> Optional[Any]:
        """Получить сервис (опционально)"""
        try:
            return self.get(interface, name)
        except ValueError:
            return None
    
    def resolve_dependencies(self, service_class: Type) -> Any:
        """Разрешить зависимости для класса"""
        # Простая реализация - в реальном проекте можно использовать
        # библиотеки типа dependency-injector или создать более сложную логику
        return service_class()
    
    def register_dependencies(self, service_name: str, dependencies: List[str]):
        """Зарегистрировать зависимости сервиса"""
        self._dependencies[service_name] = dependencies
        logger.info(f"Registered dependencies for {service_name}: {dependencies}")
    
    def get_dependencies(self, service_name: str) -> List[str]:
        """Получить зависимости сервиса"""
        return self._dependencies.get(service_name, [])
    
    def validate_dependencies(self) -> bool:
        """Проверить корректность зависимостей"""
        for service_name, deps in self._dependencies.items():
            for dep in deps:
                if dep not in self._services and dep not in self._factories:
                    logger.error(f"Missing dependency: {dep} for service {service_name}")
                    return False
        
        logger.info("Dependency validation passed")
        return True
    
    def clear(self):
        """Очистить контейнер"""
        self._services.clear()
        self._factories.clear()
        self._singletons.clear()
        self._dependencies.clear()
        logger.info("DI Container cleared")

# Глобальный контейнер зависимостей
_di_container: Optional[DIContainer] = None

def get_di_container() -> DIContainer:
    """Получить глобальный контейнер зависимостей"""
    global _di_container
    if _di_container is None:
        _di_container = DIContainer()
    return _di_container

def configure_dependencies():
    """Настроить зависимости приложения"""
    container = get_di_container()
    
    try:
        # Регистрируем сервисы
        from backend.services.rbac_service import RBACService
        from backend.services.mfa_service import MFAService
        from backend.services.ai.ai_service import AIService
        from backend.controllers.project_controller import ProjectController
        from backend.controllers.ai_controller import AIController
        from backend.factories.service_factory import ConcreteServiceFactory
        
        container.register_singleton(RBACService, RBACService)
        container.register_singleton(MFAService, MFAService)
        container.register_singleton(AIService, AIService)
        container.register_singleton(ProjectController, ProjectController)
        container.register_singleton(AIController, AIController)
        container.register_singleton(ConcreteServiceFactory, ConcreteServiceFactory)
        
        logger.info("Dependencies configured successfully")
        
    except ImportError as e:
        logger.warning(f"Failed to configure some dependencies: {e}")