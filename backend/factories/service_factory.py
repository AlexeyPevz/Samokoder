"""
Service Factory
Фабрика для создания сервисов
"""

import logging
from typing import Dict, Type, Any, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class ServiceFactory(ABC):
    """Абстрактная фабрика сервисов"""
    
    @abstractmethod
    def create_service(self, service_type: str, **kwargs) -> Any:
        """Создать сервис указанного типа"""
        pass
    
    @abstractmethod
    def get_available_services(self) -> list[str]:
        """Получить список доступных типов сервисов"""
        pass

class ConcreteServiceFactory(ServiceFactory):
    """Конкретная фабрика сервисов"""
    
    def __init__(self):
        self._service_registry: Dict[str, Type] = {}
        self._service_instances: Dict[str, Any] = {}
        self._register_default_services()
    
    def _register_default_services(self):
        """Регистрация сервисов по умолчанию"""
        try:
            from backend.services.rbac_service import RBACService
            from backend.services.mfa_service import MFAService
            from backend.services.ai.ai_service import AIService
            from backend.controllers.project_controller import ProjectController
            from backend.controllers.ai_controller import AIController
            
            self._service_registry.update({
                "rbac": RBACService,
                "mfa": MFAService,
                "ai": AIService,
                "project_controller": ProjectController,
                "ai_controller": AIController
            })
            
            logger.info("Default services registered")
        except ImportError as e:
            logger.warning(f"Failed to register some services: {e}")
    
    def register_service(self, service_type: str, service_class: Type):
        """Зарегистрировать новый тип сервиса"""
        self._service_registry[service_type] = service_class
        logger.info(f"Registered service: {service_type}")
    
    def create_service(self, service_type: str, singleton: bool = True, **kwargs) -> Any:
        """Создать сервис указанного типа"""
        if service_type not in self._service_registry:
            raise ValueError(f"Unknown service type: {service_type}")
        
        # Если singleton и уже создан, возвращаем существующий
        if singleton and service_type in self._service_instances:
            return self._service_instances[service_type]
        
        # Создаем новый экземпляр
        service_class = self._service_registry[service_type]
        instance = service_class(**kwargs)
        
        # Сохраняем если singleton
        if singleton:
            self._service_instances[service_type] = instance
        
        logger.debug(f"Created service: {service_type}")
        return instance
    
    def get_available_services(self) -> list[str]:
        """Получить список доступных типов сервисов"""
        return list(self._service_registry.keys())
    
    def get_service_instance(self, service_type: str) -> Optional[Any]:
        """Получить существующий экземпляр сервиса"""
        return self._service_instances.get(service_type)
    
    def clear_instances(self):
        """Очистить все экземпляры сервисов"""
        self._service_instances.clear()
        logger.info("All service instances cleared")

def get_service_factory() -> ConcreteServiceFactory:
    """Получить фабрику сервисов (использует DI контейнер)"""
    return ConcreteServiceFactory()