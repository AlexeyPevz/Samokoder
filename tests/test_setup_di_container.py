"""
Тесты для backend/core/setup.py - Dependency Injection Container Setup
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import logging

from backend.core.setup import (
    setup_di_container,
    get_ai_service,
    get_database_service,
    get_supabase_service
)
from backend.core.container import container
from backend.contracts.ai_service import AIServiceProtocol
from backend.contracts.database import DatabaseServiceProtocol
from backend.contracts.supabase_service import SupabaseServiceProtocol


class TestSetupDIContainer:
    """Тесты для setup_di_container функции"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        # Очищаем контейнер перед каждым тестом
        container._services = {}

    @patch('backend.core.setup.logger')
    @patch('backend.core.setup.container')
    def test_setup_di_container_registers_ai_service(self, mock_container, mock_logger):
        """Тест регистрации AI Service"""
        # Act
        setup_di_container()
        
        # Assert
        # Проверяем, что register был вызван для AIServiceProtocol
        assert mock_container.register.call_count >= 1
        mock_logger.info.assert_called()
        mock_logger.debug.assert_called()

    @patch('backend.core.setup.logger')
    @patch('backend.core.setup.container')
    def test_setup_di_container_registers_database_service(self, mock_container, mock_logger):
        """Тест регистрации Database Service"""
        # Act
        setup_di_container()
        
        # Assert
        # Проверяем, что register был вызван для DatabaseService
        assert mock_container.register.call_count >= 2

    @patch('backend.core.setup.logger')
    @patch('backend.core.setup.container')
    def test_setup_di_container_registers_supabase_service(self, mock_container, mock_logger):
        """Тест регистрации Supabase Service"""
        # Act
        setup_di_container()
        
        # Assert
        # Проверяем, что register был вызван для SupabaseService
        assert mock_container.register.call_count >= 3

    @patch('backend.core.setup.logger')
    @patch('backend.core.setup.container')
    def test_setup_di_container_logs_completion(self, mock_container, mock_logger):
        """Тест логирования завершения настройки"""
        mock_container.get_registered_services.return_value = {
            'AIServiceProtocol': 'AIServiceImpl',
            'DatabaseServiceProtocol': 'DatabaseServiceImpl'
        }
        
        # Act
        setup_di_container()
        
        # Assert
        mock_logger.info.assert_any_call("Dependency Injection container setup complete")
        mock_logger.info.assert_any_call("Registered services: ['AIServiceProtocol', 'DatabaseServiceProtocol']")

    @patch('backend.core.setup.logger')
    @patch('backend.core.setup.container')
    def test_setup_di_container_handles_exception(self, mock_container, mock_logger):
        """Тест обработки исключений при настройке"""
        mock_container.register.side_effect = Exception("Registration failed")
        
        # Act & Assert
        with pytest.raises(Exception):
            setup_di_container()

    @patch('backend.core.setup.container')
    def test_get_ai_service_returns_service(self, mock_container):
        """Тест получения AI Service"""
        mock_service = Mock(spec=AIServiceProtocol)
        mock_container.get.return_value = mock_service
        
        # Act
        result = get_ai_service()
        
        # Assert
        assert result == mock_service
        mock_container.get.assert_called_once_with(AIServiceProtocol)

    @patch('backend.core.setup.container')
    def test_get_database_service_returns_service(self, mock_container):
        """Тест получения Database Service"""
        mock_service = Mock(spec=DatabaseServiceProtocol)
        mock_container.get.return_value = mock_service
        
        # Act
        result = get_database_service()
        
        # Assert
        assert result == mock_service
        mock_container.get.assert_called_once_with(DatabaseServiceProtocol)

    @patch('backend.core.setup.container')
    def test_get_supabase_service_returns_service(self, mock_container):
        """Тест получения Supabase Service"""
        mock_service = Mock(spec=SupabaseServiceProtocol)
        mock_container.get.return_value = mock_service
        
        # Act
        result = get_supabase_service()
        
        # Assert
        assert result == mock_service
        mock_container.get.assert_called_once_with(SupabaseServiceProtocol)

    @patch('backend.core.setup.container')
    def test_get_ai_service_handles_exception(self, mock_container):
        """Тест обработки исключений при получении AI Service"""
        mock_container.get.side_effect = Exception("Service not found")
        
        # Act & Assert
        with pytest.raises(Exception):
            get_ai_service()

    @patch('backend.core.setup.container')
    def test_get_database_service_handles_exception(self, mock_container):
        """Тест обработки исключений при получении Database Service"""
        mock_container.get.side_effect = Exception("Service not found")
        
        # Act & Assert
        with pytest.raises(Exception):
            get_database_service()

    @patch('backend.core.setup.container')
    def test_get_supabase_service_handles_exception(self, mock_container):
        """Тест обработки исключений при получении Supabase Service"""
        mock_container.get.side_effect = Exception("Service not found")
        
        # Act & Assert
        with pytest.raises(Exception):
            get_supabase_service()

    @patch('backend.core.setup.logger')
    def test_setup_logs_proper_messages(self, mock_logger):
        """Тест правильности сообщений логов"""
        with patch('backend.core.setup.container') as mock_container:
            mock_container.get_registered_services.return_value = {}
            
            # Act
            setup_di_container()
            
            # Assert
            mock_logger.info.assert_any_call("Setting up Dependency Injection container...")
            mock_logger.debug.assert_any_call("Registered AIServiceProtocol -> AIServiceImpl")
            mock_logger.debug.assert_any_call("Registered DatabaseServiceProtocol -> DatabaseServiceImpl")
            mock_logger.debug.assert_any_call("Registered SupabaseServiceProtocol -> SupabaseServiceImpl")

    def test_setup_di_container_imports_work(self):
        """Тест что все импорты работают корректно"""
        # Это тест на то, что модуль может быть импортирован без ошибок
        import backend.core.setup
        assert hasattr(backend.core.setup, 'setup_di_container')
        assert hasattr(backend.core.setup, 'get_ai_service')
        assert hasattr(backend.core.setup, 'get_database_service')
        assert hasattr(backend.core.setup, 'get_supabase_service')

    @patch('backend.core.setup.container')
    def test_container_setup_on_import(self, mock_container):
        """Тест что контейнер настраивается при импорте"""
        # При импорте модуля должна вызываться setup_di_container
        # Это происходит в строке 56 файла
        with patch('backend.core.setup.setup_di_container') as mock_setup:
            import importlib
            import backend.core.setup
            importlib.reload(backend.core.setup)
            # setup_di_container должна быть вызвана при импорте