"""
Architecture Layers
Определение архитектурных слоев
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class Layer(ABC):
    """Абстрактный базовый класс для архитектурных слоев"""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
    
    @abstractmethod
    async def process(self, data: Any) -> Any:
        """Обработать данные в слое"""
        pass
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"

class PresentationLayer(Layer):
    """Слой представления (API endpoints)"""
    
    def __init__(self):
        super().__init__("presentation")
        self._controllers = {}
    
    def register_controller(self, name: str, controller):
        """Зарегистрировать контроллер"""
        self._controllers[name] = controller
        self.logger.info(f"Registered controller: {name}")
    
    async def process(self, data: Any) -> Any:
        """Обработать запрос на уровне представления"""
        # Здесь будет логика маршрутизации запросов к контроллерам
        return data

class BusinessLayer(Layer):
    """Бизнес-слой (контроллеры и бизнес-логика)"""
    
    def __init__(self):
        super().__init__("business")
        self._services = {}
    
    def register_service(self, name: str, service):
        """Зарегистрировать сервис"""
        self._services[name] = service
        self.logger.info(f"Registered service: {name}")
    
    async def process(self, data: Any) -> Any:
        """Обработать данные на бизнес-уровне"""
        # Здесь будет бизнес-логика
        return data

class DataLayer(Layer):
    """Слой данных (репозитории и база данных)"""
    
    def __init__(self):
        super().__init__("data")
        self._repositories = {}
    
    def register_repository(self, name: str, repository):
        """Зарегистрировать репозиторий"""
        self._repositories[name] = repository
        self.logger.info(f"Registered repository: {name}")
    
    async def process(self, data: Any) -> Any:
        """Обработать данные на уровне данных"""
        # Здесь будет логика работы с данными
        return data

class InfrastructureLayer(Layer):
    """Инфраструктурный слой (внешние сервисы, кэш, очереди)"""
    
    def __init__(self):
        super().__init__("infrastructure")
        self._external_services = {}
    
    def register_external_service(self, name: str, service):
        """Зарегистрировать внешний сервис"""
        self._external_services[name] = service
        self.logger.info(f"Registered external service: {name}")
    
    async def process(self, data: Any) -> Any:
        """Обработать данные на инфраструктурном уровне"""
        # Здесь будет логика работы с внешними сервисами
        return data

class ApplicationLayer:
    """Слой приложения - координирует все слои"""
    
    def __init__(self):
        self.presentation = PresentationLayer()
        self.business = BusinessLayer()
        self.data = DataLayer()
        self.infrastructure = InfrastructureLayer()
        self.logger = logging.getLogger(f"{__name__}.application")
    
    async def process_request(self, request_data: Any) -> Any:
        """Обработать запрос через все слои"""
        try:
            # Обработка через слои в правильном порядке
            data = request_data
            
            # Инфраструктурный слой (кэш, внешние сервисы)
            data = await self.infrastructure.process(data)
            
            # Слой данных (репозитории)
            data = await self.data.process(data)
            
            # Бизнес-слой (контроллеры, сервисы)
            data = await self.business.process(data)
            
            # Слой представления (API)
            data = await self.presentation.process(data)
            
            return data
            
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            raise
    
    def get_layer_dependencies(self) -> Dict[str, List[str]]:
        """Получить зависимости между слоями"""
        return {
            "presentation": ["business"],
            "business": ["data", "infrastructure"],
            "data": ["infrastructure"],
            "infrastructure": []
        }
    
    def validate_architecture(self) -> bool:
        """Проверить корректность архитектуры"""
        dependencies = self.get_layer_dependencies()
        
        # Проверяем, что нет циклических зависимостей
        for layer, deps in dependencies.items():
            if layer in deps:
                self.logger.error(f"Circular dependency detected in {layer}")
                return False
        
        self.logger.info("Architecture validation passed")
        return True

# Глобальный экземпляр слоя приложения
_application_layer: Optional[ApplicationLayer] = None

def get_application_layer() -> ApplicationLayer:
    """Получить слой приложения"""
    global _application_layer
    if _application_layer is None:
        _application_layer = ApplicationLayer()
    return _application_layer