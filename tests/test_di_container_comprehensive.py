#!/usr/bin/env python3
"""
Комплексные тесты для DI Container
"""

import pytest
from unittest.mock import Mock, patch
from typing import Protocol
from backend.core.container import (
    DIContainer,
    get_service,
    get_service_sync,
    get_optional_service,
    get_optional_service_sync,
    cached_get_service_sync,
    container
)


# Тестовые интерфейсы и реализации
class TestInterface(Protocol):
    def do_something(self) -> str: ...

class TestImplementation:
    def __init__(self):
        self.value = "test_value"
    
    def do_something(self) -> str:
        return "test_result"

class TestInterface2(Protocol):
    def do_other_thing(self) -> int: ...

class TestImplementation2:
    def do_other_thing(self) -> int:
        return 42

class TestSingletonImplementation:
    def __init__(self):
        self.id = id(self)  # Уникальный ID для проверки синглтона


class TestDIContainerComprehensive:
    """Комплексные тесты для DIContainer"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.container = DIContainer()
    
    def test_init(self):
        """Тест инициализации контейнера"""
        assert len(self.container._services) == 0
        assert len(self.container._instances) == 0
        assert len(self.container._factories) == 0
        assert len(self.container._singletons) == 0
        assert self.container._lock is not None
    
    def test_register_implementation(self):
        """Тест регистрации реализации"""
        self.container.register(TestInterface, TestImplementation)
        
        assert TestInterface in self.container._services
        assert self.container._services[TestInterface] == TestImplementation
        assert self.container._singletons[TestInterface] is True
    
    def test_register_implementation_non_singleton(self):
        """Тест регистрации не-синглтон реализации"""
        self.container.register(TestInterface, TestImplementation, singleton=False)
        
        assert TestInterface in self.container._services
        assert self.container._services[TestInterface] == TestImplementation
        assert self.container._singletons[TestInterface] is False
    
    def test_register_factory(self):
        """Тест регистрации фабрики"""
        def factory():
            return TestImplementation()
        
        self.container.register_factory(TestInterface, factory)
        
        assert TestInterface in self.container._factories
        assert self.container._factories[TestInterface] == factory
        assert self.container._singletons[TestInterface] is True
    
    def test_register_factory_non_singleton(self):
        """Тест регистрации не-синглтон фабрики"""
        def factory():
            return TestImplementation()
        
        self.container.register_factory(TestInterface, factory, singleton=False)
        
        assert TestInterface in self.container._factories
        assert self.container._factories[TestInterface] == factory
        assert self.container._singletons[TestInterface] is False
    
    def test_register_instance(self):
        """Тест регистрации экземпляра"""
        instance = TestImplementation()
        
        self.container.register_instance(TestInterface, instance)
        
        assert TestInterface in self.container._instances
        assert self.container._instances[TestInterface] == instance
        assert self.container._singletons[TestInterface] is True
    
    @pytest.mark.asyncio
    async def test_get_registered_instance(self):
        """Тест получения зарегистрированного экземпляра"""
        instance = TestImplementation()
        self.container.register_instance(TestInterface, instance)
        
        result = await self.container.get(TestInterface)
        
        assert result == instance
        assert result.do_something() == "test_result"
    
    @pytest.mark.asyncio
    async def test_get_singleton_implementation(self):
        """Тест получения синглтон реализации"""
        self.container.register(TestInterface, TestSingletonImplementation)
        
        instance1 = await self.container.get(TestInterface)
        instance2 = await self.container.get(TestInterface)
        
        assert instance1 == instance2
        assert instance1.id == instance2.id
    
    @pytest.mark.asyncio
    async def test_get_non_singleton_implementation(self):
        """Тест получения не-синглтон реализации"""
        self.container.register(TestInterface, TestSingletonImplementation, singleton=False)
        
        instance1 = await self.container.get(TestInterface)
        instance2 = await self.container.get(TestInterface)
        
        assert instance1 != instance2
        assert instance1.id != instance2.id
    
    @pytest.mark.asyncio
    async def test_get_singleton_factory(self):
        """Тест получения синглтон фабрики"""
        def factory():
            return TestSingletonImplementation()
        
        self.container.register_factory(TestInterface, factory)
        
        instance1 = await self.container.get(TestInterface)
        instance2 = await self.container.get(TestInterface)
        
        assert instance1 == instance2
        assert instance1.id == instance2.id
    
    @pytest.mark.asyncio
    async def test_get_non_singleton_factory(self):
        """Тест получения не-синглтон фабрики"""
        def factory():
            return TestSingletonImplementation()
        
        self.container.register_factory(TestInterface, factory, singleton=False)
        
        instance1 = await self.container.get(TestInterface)
        instance2 = await self.container.get(TestInterface)
        
        assert instance1 != instance2
        assert instance1.id != instance2.id
    
    @pytest.mark.asyncio
    async def test_get_unregistered_service(self):
        """Тест получения незарегистрированного сервиса"""
        with pytest.raises(ValueError, match="No registration found for TestInterface"):
            await self.container.get(TestInterface)
    
    def test_get_sync_registered_instance(self):
        """Тест синхронного получения зарегистрированного экземпляра"""
        instance = TestImplementation()
        self.container.register_instance(TestInterface, instance)
        
        result = self.container.get_sync(TestInterface)
        
        assert result == instance
        assert result.do_something() == "test_result"
    
    def test_get_sync_singleton_implementation(self):
        """Тест синхронного получения синглтон реализации"""
        self.container.register(TestInterface, TestSingletonImplementation)
        
        instance1 = self.container.get_sync(TestInterface)
        instance2 = self.container.get_sync(TestInterface)
        
        assert instance1 == instance2
        assert instance1.id == instance2.id
    
    def test_get_sync_non_singleton_implementation(self):
        """Тест синхронного получения не-синглтон реализации"""
        self.container.register(TestInterface, TestSingletonImplementation, singleton=False)
        
        instance1 = self.container.get_sync(TestInterface)
        instance2 = self.container.get_sync(TestInterface)
        
        assert instance1 != instance2
        assert instance1.id != instance2.id
    
    def test_get_sync_unregistered_service(self):
        """Тест синхронного получения незарегистрированного сервиса"""
        with pytest.raises(ValueError, match="No registration found for TestInterface"):
            self.container.get_sync(TestInterface)
    
    @pytest.mark.asyncio
    async def test_get_optional_registered_service(self):
        """Тест получения опционального зарегистрированного сервиса"""
        instance = TestImplementation()
        self.container.register_instance(TestInterface, instance)
        
        result = await self.container.get_optional(TestInterface)
        
        assert result == instance
    
    @pytest.mark.asyncio
    async def test_get_optional_unregistered_service(self):
        """Тест получения опционального незарегистрированного сервиса"""
        result = await self.container.get_optional(TestInterface)
        
        assert result is None
    
    def test_get_optional_sync_registered_service(self):
        """Тест синхронного получения опционального зарегистрированного сервиса"""
        instance = TestImplementation()
        self.container.register_instance(TestInterface, instance)
        
        result = self.container.get_optional_sync(TestInterface)
        
        assert result == instance
    
    def test_get_optional_sync_unregistered_service(self):
        """Тест синхронного получения опционального незарегистрированного сервиса"""
        result = self.container.get_optional_sync(TestInterface)
        
        assert result is None
    
    def test_is_registered_implementation(self):
        """Тест проверки регистрации реализации"""
        assert self.container.is_registered(TestInterface) is False
        
        self.container.register(TestInterface, TestImplementation)
        
        assert self.container.is_registered(TestInterface) is True
    
    def test_is_registered_factory(self):
        """Тест проверки регистрации фабрики"""
        assert self.container.is_registered(TestInterface) is False
        
        def factory():
            return TestImplementation()
        
        self.container.register_factory(TestInterface, factory)
        
        assert self.container.is_registered(TestInterface) is True
    
    def test_is_registered_instance(self):
        """Тест проверки регистрации экземпляра"""
        assert self.container.is_registered(TestInterface) is False
        
        instance = TestImplementation()
        self.container.register_instance(TestInterface, instance)
        
        assert self.container.is_registered(TestInterface) is True
    
    def test_clear(self):
        """Тест очистки всех регистраций"""
        # Регистрируем разные типы сервисов
        self.container.register(TestInterface, TestImplementation)
        
        def factory():
            return TestImplementation()
        
        self.container.register_factory(TestInterface2, factory)
        
        instance = TestImplementation()
        self.container.register_instance(TestInterface, instance)
        
        # Проверяем что сервисы зарегистрированы
        assert len(self.container._services) > 0
        assert len(self.container._factories) > 0
        assert len(self.container._instances) > 0
        assert len(self.container._singletons) > 0
        
        # Очищаем
        self.container.clear()
        
        # Проверяем что все очищено
        assert len(self.container._services) == 0
        assert len(self.container._factories) == 0
        assert len(self.container._instances) == 0
        assert len(self.container._singletons) == 0
    
    def test_get_registered_services(self):
        """Тест получения списка зарегистрированных сервисов"""
        # Изначально пусто
        services = self.container.get_registered_services()
        assert len(services) == 0
        
        # Регистрируем разные типы сервисов для разных интерфейсов
        self.container.register(TestInterface, TestImplementation)
        
        def factory():
            return TestImplementation2()
        
        self.container.register_factory(TestInterface2, factory)
        
        # Получаем список сервисов
        services = self.container.get_registered_services()
        
        assert len(services) == 2
        assert "TestInterface" in services
        assert "TestInterface2" in services
        assert "Implementation: TestImplementation" in services.values()
        assert "Factory: factory" in services.values()


class TestDIContainerGlobalFunctions:
    """Тесты для глобальных функций DI Container"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        # Очищаем глобальный контейнер
        container.clear()
    
    @pytest.mark.asyncio
    async def test_get_service_async(self):
        """Тест асинхронного получения сервиса"""
        instance = TestImplementation()
        container.register_instance(TestInterface, instance)
        
        result = await get_service(TestInterface)
        
        assert result == instance
    
    def test_get_service_sync(self):
        """Тест синхронного получения сервиса"""
        instance = TestImplementation()
        container.register_instance(TestInterface, instance)
        
        result = get_service_sync(TestInterface)
        
        assert result == instance
    
    @pytest.mark.asyncio
    async def test_get_optional_service_async(self):
        """Тест асинхронного получения опционального сервиса"""
        instance = TestImplementation()
        container.register_instance(TestInterface, instance)
        
        result = await get_optional_service(TestInterface)
        
        assert result == instance
    
    @pytest.mark.asyncio
    async def test_get_optional_service_async_none(self):
        """Тест асинхронного получения опционального сервиса (None)"""
        result = await get_optional_service(TestInterface)
        
        assert result is None
    
    def test_get_optional_service_sync(self):
        """Тест синхронного получения опционального сервиса"""
        instance = TestImplementation()
        container.register_instance(TestInterface, instance)
        
        result = get_optional_service_sync(TestInterface)
        
        assert result == instance
    
    def test_get_optional_service_sync_none(self):
        """Тест синхронного получения опционального сервиса (None)"""
        result = get_optional_service_sync(TestInterface)
        
        assert result is None
    
    def test_cached_get_service_sync(self):
        """Тест кэшированного получения сервиса"""
        instance = TestImplementation()
        container.register_instance(TestInterface, instance)
        
        result1 = cached_get_service_sync(TestInterface)
        result2 = cached_get_service_sync(TestInterface)
        
        assert result1 == result2
        assert result1 == instance
    
    def test_cached_get_service_sync_different_services(self):
        """Тест кэшированного получения разных сервисов"""
        instance1 = TestImplementation()
        instance2 = TestImplementation2()
        
        container.register_instance(TestInterface, instance1)
        container.register_instance(TestInterface2, instance2)
        
        result1 = cached_get_service_sync(TestInterface)
        result2 = cached_get_service_sync(TestInterface2)
        
        # Проверяем что получаем правильные типы
        assert isinstance(result1, TestImplementation)
        assert isinstance(result2, TestImplementation2)
        assert result1.do_something() == "test_result"
        assert result2.do_other_thing() == 42