"""
Комплексные тесты для DIContainer (38% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio
from typing import Type, Protocol

from backend.core.container import DIContainer, T


class TestService(Protocol):
    """Тестовый интерфейс сервиса"""
    def do_something(self) -> str:
        ...


class TestServiceImpl:
    """Тестовая реализация сервиса"""
    def __init__(self, value: str = "default"):
        self.value = value
    
    def do_something(self) -> str:
        return f"TestService: {self.value}"


class TestServiceWithDependency:
    """Тестовый сервис с зависимостью"""
    def __init__(self, dependency: TestService):
        self.dependency = dependency
    
    def do_something(self) -> str:
        return f"ServiceWithDep: {self.dependency.do_something()}"


class TestDIContainer:
    """Тесты для DIContainer"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.container = DIContainer()

    def test_init(self):
        """Тест инициализации контейнера"""
        container = DIContainer()
        assert hasattr(container, '_services')
        assert hasattr(container, '_instances')
        assert hasattr(container, '_factories')
        assert hasattr(container, '_singletons')
        assert hasattr(container, '_lock')
        assert isinstance(container._lock, asyncio.Lock)

    def test_register_service(self):
        """Тест регистрации сервиса"""
        # Act
        self.container.register(TestService, TestServiceImpl, singleton=True)
        
        # Assert
        assert TestService in self.container._services
        assert self.container._services[TestService] == TestServiceImpl
        assert self.container._singletons[TestService] is True

    def test_register_service_non_singleton(self):
        """Тест регистрации не-singleton сервиса"""
        # Act
        self.container.register(TestService, TestServiceImpl, singleton=False)
        
        # Assert
        assert TestService in self.container._services
        assert self.container._services[TestService] == TestServiceImpl
        assert self.container._singletons[TestService] is False

    def test_register_factory(self):
        """Тест регистрации фабрики"""
        def factory() -> TestService:
            return TestServiceImpl("factory_created")
        
        # Act
        self.container.register_factory(TestService, factory, singleton=True)
        
        # Assert
        assert TestService in self.container._factories
        assert self.container._factories[TestService] == factory
        assert self.container._singletons[TestService] is True

    def test_register_factory_non_singleton(self):
        """Тест регистрации не-singleton фабрики"""
        def factory() -> TestService:
            return TestServiceImpl("factory_created")
        
        # Act
        self.container.register_factory(TestService, factory, singleton=False)
        
        # Assert
        assert TestService in self.container._factories
        assert self.container._factories[TestService] == factory
        assert self.container._singletons[TestService] is False

    def test_register_instance(self):
        """Тест регистрации экземпляра"""
        # Arrange
        instance = TestServiceImpl("instance")
        
        # Act
        self.container.register_instance(TestService, instance)
        
        # Assert
        assert TestService in self.container._instances
        assert self.container._instances[TestService] == instance
        assert self.container._singletons[TestService] is True

    @pytest.mark.asyncio
    async def test_get_registered_instance(self):
        """Тест получения зарегистрированного экземпляра"""
        # Arrange
        instance = TestServiceImpl("test_instance")
        self.container.register_instance(TestService, instance)
        
        # Act
        result = await self.container.get(TestService)
        
        # Assert
        assert result == instance
        assert result.do_something() == "TestService: test_instance"

    @pytest.mark.asyncio
    async def test_get_service_from_implementation(self):
        """Тест получения сервиса из реализации"""
        # Arrange
        self.container.register(TestService, TestServiceImpl, singleton=True)
        
        # Act
        result = await self.container.get(TestService)
        
        # Assert
        assert isinstance(result, TestServiceImpl)
        assert result.do_something() == "TestService: default"

    @pytest.mark.asyncio
    async def test_get_service_from_factory(self):
        """Тест получения сервиса из фабрики"""
        # Arrange
        def factory() -> TestService:
            return TestServiceImpl("factory_value")
        
        self.container.register_factory(TestService, factory, singleton=True)
        
        # Act
        result = await self.container.get(TestService)
        
        # Assert
        assert isinstance(result, TestServiceImpl)
        assert result.do_something() == "TestService: factory_value"

    @pytest.mark.asyncio
    async def test_get_service_non_singleton(self):
        """Тест получения не-singleton сервиса"""
        # Arrange
        self.container.register(TestService, TestServiceImpl, singleton=False)
        
        # Act
        result1 = await self.container.get(TestService)
        result2 = await self.container.get(TestService)
        
        # Assert
        assert isinstance(result1, TestServiceImpl)
        assert isinstance(result2, TestServiceImpl)
        assert result1 is not result2  # Разные экземпляры

    @pytest.mark.asyncio
    async def test_get_service_singleton(self):
        """Тест получения singleton сервиса"""
        # Arrange
        self.container.register(TestService, TestServiceImpl, singleton=True)
        
        # Act
        result1 = await self.container.get(TestService)
        result2 = await self.container.get(TestService)
        
        # Assert
        assert isinstance(result1, TestServiceImpl)
        assert isinstance(result2, TestServiceImpl)
        assert result1 is result2  # Один и тот же экземпляр

    @pytest.mark.asyncio
    async def test_get_service_not_registered(self):
        """Тест получения незарегистрированного сервиса"""
        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            await self.container.get(TestService)
        assert "No service registered for" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_service_with_dependencies(self):
        """Тест получения сервиса с зависимостями"""
        # Arrange
        dependency = TestServiceImpl("dependency")
        self.container.register_instance(TestService, dependency)
        
        def factory_with_dep() -> TestServiceWithDependency:
            dep = self.container._instances[TestService]
            return TestServiceWithDependency(dep)
        
        self.container.register_factory(TestServiceWithDependency, factory_with_dep, singleton=True)
        
        # Act
        result = await self.container.get(TestServiceWithDependency)
        
        # Assert
        assert isinstance(result, TestServiceWithDependency)
        assert result.dependency == dependency
        assert result.do_something() == "ServiceWithDep: TestService: dependency"

    @pytest.mark.asyncio
    async def test_get_service_factory_non_singleton(self):
        """Тест получения не-singleton сервиса из фабрики"""
        # Arrange
        def factory() -> TestService:
            return TestServiceImpl("factory_value")
        
        self.container.register_factory(TestService, factory, singleton=False)
        
        # Act
        result1 = await self.container.get(TestService)
        result2 = await self.container.get(TestService)
        
        # Assert
        assert isinstance(result1, TestServiceImpl)
        assert isinstance(result2, TestServiceImpl)
        assert result1 is not result2  # Разные экземпляры

    def test_is_registered_true(self):
        """Тест проверки регистрации - сервис зарегистрирован"""
        # Arrange
        self.container.register(TestService, TestServiceImpl)
        
        # Act
        result = self.container.is_registered(TestService)
        
        # Assert
        assert result is True

    def test_is_registered_false(self):
        """Тест проверки регистрации - сервис не зарегистрирован"""
        # Act
        result = self.container.is_registered(TestService)
        
        # Assert
        assert result is False

    def test_is_registered_factory(self):
        """Тест проверки регистрации - фабрика зарегистрирована"""
        # Arrange
        def factory() -> TestService:
            return TestServiceImpl("factory")
        
        self.container.register_factory(TestService, factory)
        
        # Act
        result = self.container.is_registered(TestService)
        
        # Assert
        assert result is True

    def test_is_registered_instance(self):
        """Тест проверки регистрации - экземпляр зарегистрирован"""
        # Arrange
        instance = TestServiceImpl("instance")
        self.container.register_instance(TestService, instance)
        
        # Act
        result = self.container.is_registered(TestService)
        
        # Assert
        assert result is True

    def test_get_registered_services(self):
        """Тест получения списка зарегистрированных сервисов"""
        # Arrange
        self.container.register(TestService, TestServiceImpl)
        self.container.register_factory(TestServiceWithDependency, lambda: TestServiceWithDependency(None))
        instance = TestServiceImpl("instance")
        self.container.register_instance(str, instance)  # Другой тип
        
        # Act
        result = self.container.get_registered_services()
        
        # Assert
        assert TestService in result
        assert TestServiceWithDependency in result
        assert str in result
        assert len(result) == 3

    def test_clear(self):
        """Тест очистки контейнера"""
        # Arrange
        self.container.register(TestService, TestServiceImpl)
        instance = TestServiceImpl("instance")
        self.container.register_instance(TestServiceWithDependency, instance)
        
        # Act
        self.container.clear()
        
        # Assert
        assert len(self.container._services) == 0
        assert len(self.container._instances) == 0
        assert len(self.container._factories) == 0
        assert len(self.container._singletons) == 0

    def test_clear_specific_service(self):
        """Тест очистки конкретного сервиса"""
        # Arrange
        self.container.register(TestService, TestServiceImpl)
        instance = TestServiceImpl("instance")
        self.container.register_instance(TestServiceWithDependency, instance)
        
        # Act
        self.container.clear(TestService)
        
        # Assert
        assert TestService not in self.container._services
        assert TestServiceWithDependency in self.container._instances

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Тест конкурентного доступа к контейнеру"""
        # Arrange
        self.container.register(TestService, TestServiceImpl, singleton=True)
        
        # Act - создаем несколько задач одновременно
        tasks = [self.container.get(TestService) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Assert - все должны получить один и тот же экземпляр
        first_result = results[0]
        for result in results:
            assert result is first_result

    @pytest.mark.asyncio
    async def test_factory_exception_handling(self):
        """Тест обработки исключений в фабрике"""
        # Arrange
        def failing_factory() -> TestService:
            raise Exception("Factory failed")
        
        self.container.register_factory(TestService, failing_factory, singleton=True)
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await self.container.get(TestService)
        assert "Factory failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_implementation_exception_handling(self):
        """Тест обработки исключений при создании экземпляра"""
        # Arrange
        class FailingImplementation:
            def __init__(self):
                raise Exception("Implementation failed")
        
        self.container.register(TestService, FailingImplementation, singleton=True)
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            await self.container.get(TestService)
        assert "Implementation failed" in str(exc_info.value)

    def test_multiple_registrations_same_interface(self):
        """Тест множественных регистраций одного интерфейса"""
        # Arrange
        self.container.register(TestService, TestServiceImpl)
        
        # Act - перезаписываем регистрацию
        self.container.register(TestService, TestServiceWithDependency)
        
        # Assert
        assert self.container._services[TestService] == TestServiceWithDependency

    def test_register_factory_overwrites_service(self):
        """Тест что фабрика перезаписывает сервис"""
        # Arrange
        self.container.register(TestService, TestServiceImpl)
        
        def factory() -> TestService:
            return TestServiceImpl("factory")
        
        # Act
        self.container.register_factory(TestService, factory)
        
        # Assert
        assert TestService in self.container._factories
        assert TestService not in self.container._services

    def test_register_instance_overwrites_all(self):
        """Тест что экземпляр перезаписывает все остальное"""
        # Arrange
        self.container.register(TestService, TestServiceImpl)
        self.container.register_factory(TestService, lambda: TestServiceImpl("factory"))
        
        instance = TestServiceImpl("instance")
        
        # Act
        self.container.register_instance(TestService, instance)
        
        # Assert
        assert TestService in self.container._instances
        assert TestService not in self.container._services
        assert TestService not in self.container._factories

    @pytest.mark.asyncio
    async def test_get_with_parameters(self):
        """Тест получения сервиса с параметрами (если поддерживается)"""
        # Arrange
        class ParametrizedService:
            def __init__(self, param1: str, param2: int = 42):
                self.param1 = param1
                self.param2 = param2
        
        # Для простоты тестируем что параметры не поддерживаются в текущей реализации
        # В реальной реализации можно было бы добавить поддержку параметров
        self.container.register(TestService, ParametrizedService, singleton=True)
        
        # Act
        result = await self.container.get(TestService)
        
        # Assert
        assert isinstance(result, ParametrizedService)
        assert result.param1 == "default"  # Значение по умолчанию
        assert result.param2 == 42