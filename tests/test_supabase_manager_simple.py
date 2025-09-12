"""
Упрощенные тесты для Supabase Manager (33% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio
from datetime import datetime, timedelta

from backend.services.supabase_manager import (
    SupabaseConfig,
    SupabaseConnectionManager
)


class TestSupabaseConfig:
    """Тесты для SupabaseConfig"""

    def test_init_default(self):
        """Тест инициализации с параметрами по умолчанию"""
        config = SupabaseConfig()
        
        assert config.max_connections == 10
        assert config.connection_timeout == 30
        assert config.retry_attempts == 3
        assert config.retry_delay == 1.0
        assert config.health_check_interval == 60

    def test_init_custom(self):
        """Тест инициализации с кастомными параметрами"""
        config = SupabaseConfig(
            max_connections=20,
            connection_timeout=60,
            retry_attempts=5,
            retry_delay=2.0,
            health_check_interval=120
        )
        
        assert config.max_connections == 20
        assert config.connection_timeout == 60
        assert config.retry_attempts == 5
        assert config.retry_delay == 2.0
        assert config.health_check_interval == 120


class TestSupabaseConnectionManager:
    """Тесты для SupabaseConnectionManager"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.config = SupabaseConfig()
        self.manager = SupabaseConnectionManager(self.config)

    def test_init(self):
        """Тест инициализации"""
        assert self.manager.config == self.config
        assert self.manager._clients == {}
        assert self.manager._health_status == {}
        assert self.manager._last_health_check == {}
        assert self.manager._initialized is False

    @pytest.mark.asyncio
    @patch('backend.services.supabase_manager.create_client')
    async def test_initialize_success(self, mock_create_client):
        """Тест успешной инициализации"""
        # Arrange
        mock_client = Mock()
        mock_create_client.return_value = mock_client
        
        # Act
        await self.manager.initialize()
        
        # Assert
        assert self.manager._initialized is True
        mock_create_client.assert_called()

    @pytest.mark.asyncio
    async def test_initialize_already_initialized(self):
        """Тест инициализации уже инициализированного менеджера"""
        # Arrange
        self.manager._initialized = True
        
        # Act
        await self.manager.initialize()
        
        # Assert
        assert self.manager._initialized is True

    @pytest.mark.asyncio
    async def test_get_client_not_initialized(self):
        """Тест получения клиента без инициализации"""
        # Act & Assert
        with pytest.raises(Exception):
            await self.manager.get_client("default")

    @pytest.mark.asyncio
    async def test_get_client_initialized(self):
        """Тест получения клиента"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["default"] = mock_client
        
        # Act
        client = self.manager.get_client("default")
        
        # Assert
        assert client == mock_client

    @pytest.mark.asyncio
    async def test_get_client_not_found(self):
        """Тест получения несуществующего клиента"""
        # Arrange
        self.manager._initialized = True
        
        # Act
        client = self.manager.get_client("nonexistent")
        
        # Assert
        assert client is None

    @pytest.mark.asyncio
    async def test_execute_operation_not_initialized(self):
        """Тест выполнения операции без инициализации"""
        # Act & Assert
        with pytest.raises(Exception):
            await self.manager.execute_async(lambda client: client, "default")

    @pytest.mark.asyncio
    async def test_execute_operation_success(self):
        """Тест успешного выполнения операции"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.return_value.data = [{"id": 1}]
        self.manager._clients["default"] = mock_client
        
        def mock_operation(client, table, **kwargs):
            return client.table(table).select("id").execute().data
        
        # Act
        result = await self.manager.execute_async(mock_operation, "default", "users")
        
        # Assert
        assert result == [{"id": 1}]

    @pytest.mark.asyncio
    async def test_execute_operation_failure(self):
        """Тест неудачного выполнения операции"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.side_effect = Exception("Database error")
        self.manager._clients["default"] = mock_client
        
        def mock_operation(client, table, **kwargs):
            return client.table(table).select("id").execute().data
        
        # Act & Assert
        with pytest.raises(Exception):
            await self.manager.execute_async(mock_operation, "default", "users")

    @pytest.mark.asyncio
    async def test_health_check_not_initialized(self):
        """Тест проверки здоровья без инициализации"""
        # Act
        result = self.manager._is_client_healthy("default")
        
        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Тест успешной проверки здоровья"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.return_value.data = []
        self.manager._clients["default"] = mock_client
        
        # Act
        result = self.manager._is_client_healthy("default")
        
        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Тест неудачной проверки здоровья"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.side_effect = Exception("Connection failed")
        self.manager._clients["default"] = mock_client
        
        # Act
        result = self.manager._is_client_healthy("default")
        
        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_get_all_health_status(self):
        """Тест получения статуса всех соединений"""
        # Arrange
        self.manager._initialized = True
        self.manager._health_status = {"default": True, "backup": False}
        
        # Act
        status = self.manager.get_all_health_status()
        
        # Assert
        assert status == {"default": True, "backup": False}

    @pytest.mark.asyncio
    async def test_close_not_initialized(self):
        """Тест закрытия неинициализированного менеджера"""
        # Act
        await self.manager.close()
        
        # Assert
        assert self.manager._initialized is False

    @pytest.mark.asyncio
    async def test_close_initialized(self):
        """Тест закрытия инициализированного менеджера"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["default"] = mock_client
        
        # Act
        await self.manager.close()
        
        # Assert
        assert self.manager._initialized is False
        assert self.manager._clients == {}

    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Тест конкурентных операций"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.return_value.data = [{"id": 1}]
        self.manager._clients["default"] = mock_client
        
        def mock_operation(client, table, **kwargs):
            return client.table(table).select("id").execute().data
        
        # Act - создаем несколько задач одновременно
        tasks = [
            self.manager.execute_async(mock_operation, "default", "users")
            for _ in range(5)
        ]
        results = await asyncio.gather(*tasks)
        
        # Assert
        assert len(results) == 5
        assert all(result == [{"id": 1}] for result in results)

    @pytest.mark.asyncio
    async def test_retry_mechanism(self):
        """Тест механизма повторных попыток"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        
        # Первые два вызова завершаются ошибкой, третий - успехом
        mock_client.table.return_value.select.return_value.execute.side_effect = [
            Exception("Temporary error"),
            Exception("Temporary error"),
            Mock(data=[{"id": 1}])
        ]
        self.manager._clients["default"] = mock_client
        
        def mock_operation(client, table, **kwargs):
            return client.table(table).select("id").execute().data
        
        # Act
        result = await self.manager.execute_async(mock_operation, "default", "users")
        
        # Assert
        assert result == [{"id": 1}]

    def test_get_client_count(self):
        """Тест получения количества клиентов"""
        # Arrange
        self.manager._clients = {"default": Mock(), "backup": Mock()}
        
        # Act
        count = self.manager.get_client_count()
        
        # Assert
        assert count == 2

    def test_is_initialized(self):
        """Тест проверки инициализации"""
        # Arrange
        self.manager._initialized = True
        
        # Act
        result = self.manager.is_initialized()
        
        # Assert
        assert result is True

    def test_is_initialized_false(self):
        """Тест проверки неинициализированного состояния"""
        # Act
        result = self.manager.is_initialized()
        
        # Assert
        assert result is False