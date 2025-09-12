#!/usr/bin/env python3
"""
Тесты для Setup DI Container
"""

import pytest
from unittest.mock import Mock, patch
from backend.core.setup import (
    setup_di_container,
    get_ai_service,
    get_database_service,
    get_supabase_service
)
from backend.contracts.ai_service import AIServiceProtocol
from backend.contracts.database import DatabaseServiceProtocol
from backend.contracts.supabase_service import SupabaseServiceProtocol


class TestSetupDIContainer:
    """Тесты для setup_di_container"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        # Очищаем контейнер перед каждым тестом
        from backend.core.container import container
        container.clear()
    
    @patch('backend.core.setup.logger')
    @patch('backend.core.setup.container')
    def test_setup_di_container(self, mock_container, mock_logger):
        """Тест настройки DI контейнера"""
        # Настраиваем мок контейнера
        mock_container.get_registered_services.return_value = {
            "AIServiceProtocol": "Implementation: AIServiceImpl",
            "DatabaseServiceProtocol": "Implementation: DatabaseServiceImpl", 
            "SupabaseServiceProtocol": "Implementation: SupabaseServiceImpl"
        }
        
        # Вызываем функцию
        setup_di_container()
        
        # Проверяем что все сервисы зарегистрированы
        assert mock_container.register.call_count == 3
        
        # Проверяем регистрацию AI Service
        mock_container.register.assert_any_call(
            AIServiceProtocol, 
            mock_container.register.call_args_list[0][0][1],  # AIServiceImpl
            singleton=True
        )
        
        # Проверяем регистрацию Database Service
        mock_container.register.assert_any_call(
            DatabaseServiceProtocol,
            mock_container.register.call_args_list[1][0][1],  # DatabaseServiceImpl
            singleton=True
        )
        
        # Проверяем регистрацию Supabase Service
        mock_container.register.assert_any_call(
            SupabaseServiceProtocol,
            mock_container.register.call_args_list[2][0][1],  # SupabaseServiceImpl
            singleton=True
        )
        
        # Проверяем логирование
        mock_logger.info.assert_called()
        mock_logger.debug.assert_called()
        mock_logger.info.assert_any_call("Setting up Dependency Injection container...")
        mock_logger.info.assert_any_call("Dependency Injection container setup complete")
    
    @patch('backend.core.setup.logger')
    @patch('backend.core.setup.container')
    def test_setup_di_container_logging(self, mock_container, mock_logger):
        """Тест логирования при настройке DI контейнера"""
        mock_container.get_registered_services.return_value = {"TestService": "Implementation: TestImpl"}
        
        setup_di_container()
        
        # Проверяем что все ожидаемые логи записаны
        mock_logger.info.assert_any_call("Setting up Dependency Injection container...")
        mock_logger.debug.assert_any_call("Registered AIServiceProtocol -> AIServiceImpl")
        mock_logger.debug.assert_any_call("Registered DatabaseServiceProtocol -> DatabaseServiceImpl")
        mock_logger.debug.assert_any_call("Registered SupabaseServiceProtocol -> SupabaseServiceImpl")
        mock_logger.info.assert_any_call("Dependency Injection container setup complete")
        mock_logger.info.assert_any_call("Registered services: ['TestService']")


class TestServiceGetters:
    """Тесты для функций получения сервисов"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        # Очищаем контейнер перед каждым тестом
        from backend.core.container import container
        container.clear()
    
    @patch('backend.core.setup.container')
    def test_get_ai_service(self, mock_container):
        """Тест получения AI сервиса"""
        mock_ai_service = Mock(spec=AIServiceProtocol)
        mock_container.get.return_value = mock_ai_service
        
        result = get_ai_service()
        
        assert result == mock_ai_service
        mock_container.get.assert_called_once_with(AIServiceProtocol)
    
    @patch('backend.core.setup.container')
    def test_get_database_service(self, mock_container):
        """Тест получения Database сервиса"""
        mock_db_service = Mock(spec=DatabaseServiceProtocol)
        mock_container.get.return_value = mock_db_service
        
        result = get_database_service()
        
        assert result == mock_db_service
        mock_container.get.assert_called_once_with(DatabaseServiceProtocol)
    
    @patch('backend.core.setup.container')
    def test_get_supabase_service(self, mock_container):
        """Тест получения Supabase сервиса"""
        mock_supabase_service = Mock(spec=SupabaseServiceProtocol)
        mock_container.get.return_value = mock_supabase_service
        
        result = get_supabase_service()
        
        assert result == mock_supabase_service
        mock_container.get.assert_called_once_with(SupabaseServiceProtocol)
    
    @patch('backend.core.setup.container')
    def test_get_ai_service_error(self, mock_container):
        """Тест получения AI сервиса при ошибке"""
        mock_container.get.side_effect = ValueError("Service not registered")
        
        with pytest.raises(ValueError, match="Service not registered"):
            get_ai_service()
    
    @patch('backend.core.setup.container')
    def test_get_database_service_error(self, mock_container):
        """Тест получения Database сервиса при ошибке"""
        mock_container.get.side_effect = ValueError("Service not registered")
        
        with pytest.raises(ValueError, match="Service not registered"):
            get_database_service()
    
    @patch('backend.core.setup.container')
    def test_get_supabase_service_error(self, mock_container):
        """Тест получения Supabase сервиса при ошибке"""
        mock_container.get.side_effect = ValueError("Service not registered")
        
        with pytest.raises(ValueError, match="Service not registered"):
            get_supabase_service()


class TestSetupIntegration:
    """Интеграционные тесты для setup"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        # Очищаем контейнер перед каждым тестом
        from backend.core.container import container
        container.clear()
    
    def test_setup_integration(self):
        """Интеграционный тест настройки DI контейнера"""
        # Импортируем реальный контейнер
        from backend.core.container import container
        
        # Вызываем настройку
        setup_di_container()
        
        # Проверяем что сервисы зарегистрированы
        assert container.is_registered(AIServiceProtocol)
        assert container.is_registered(DatabaseServiceProtocol)
        assert container.is_registered(SupabaseServiceProtocol)
        
        # Проверяем что можно получить сервисы синхронно
        ai_service = container.get_sync(AIServiceProtocol)
        db_service = container.get_sync(DatabaseServiceProtocol)
        supabase_service = container.get_sync(SupabaseServiceProtocol)
        
        # Проверяем что получили экземпляры правильных типов
        assert ai_service is not None
        assert db_service is not None
        assert supabase_service is not None
    
    def test_setup_on_import(self):
        """Тест что setup вызывается при импорте модуля"""
        # Этот тест проверяет что setup_di_container вызывается при импорте
        # Поскольку setup вызывается на уровне модуля, мы просто проверяем
        # что импорт не вызывает ошибок
        from backend.core import setup
        
        assert setup.setup_di_container is not None
        assert setup.get_ai_service is not None
        assert setup.get_database_service is not None
        assert setup.get_supabase_service is not None