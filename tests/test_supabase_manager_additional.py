"""
Дополнительные тесты для Supabase Manager (45% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio
from datetime import datetime, timedelta

from backend.services.supabase_manager import (
    SupabaseConfig,
    SupabaseConnectionManager
)


class TestSupabaseManagerAdditional:
    """Дополнительные тесты для SupabaseConnectionManager"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.config = SupabaseConfig()
        self.manager = SupabaseConnectionManager(self.config)

    @pytest.mark.asyncio
    @patch('backend.services.supabase_manager.create_client')
    async def test_initialize_creates_clients(self, mock_create_client):
        """Тест инициализации создания клиентов"""
        # Arrange
        mock_client = Mock()
        mock_create_client.return_value = mock_client
        
        # Act
        await self.manager.initialize()
        
        # Assert
        assert self.manager._initialized is True
        assert mock_create_client.call_count >= 1

    @pytest.mark.asyncio
    async def test_get_client_returns_none_for_missing_client(self):
        """Тест получения клиента - возвращает None для отсутствующего клиента"""
        # Arrange
        self.manager._initialized = True
        
        # Act
        client = self.manager.get_client("missing_client")
        
        # Assert
        assert client is None

    @pytest.mark.asyncio
    async def test_execute_async_with_valid_operation(self):
        """Тест выполнения async операции с валидной операцией"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["default"] = mock_client
        
        def mock_operation(client, value):
            return f"processed_{value}"
        
        # Act
        result = await self.manager.execute_async(mock_operation, "default", "test_value")
        
        # Assert
        assert result == "processed_test_value"

    @pytest.mark.asyncio
    async def test_execute_async_with_callable_operation(self):
        """Тест выполнения async операции с callable операцией"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["default"] = mock_client
        
        mock_callable = Mock(return_value="callable_result")
        
        # Act
        result = await self.manager.execute_async(mock_callable, "default")
        
        # Assert
        assert result == "callable_result"
        mock_callable.assert_called_once_with(mock_client)

    @pytest.mark.asyncio
    async def test_execute_async_with_non_callable_operation(self):
        """Тест выполнения async операции с не-callable операцией"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["default"] = mock_client
        
        non_callable_operation = "not_callable"
        
        # Act
        result = await self.manager.execute_async(non_callable_operation, "default")
        
        # Assert
        assert result == "not_callable"

    @pytest.mark.asyncio
    async def test_execute_sync_operation_with_callable(self):
        """Тест выполнения синхронной операции с callable"""
        # Arrange
        mock_client = Mock()
        
        def mock_operation(client, value):
            return f"sync_{value}"
        
        # Act
        result = self.manager._execute_sync_operation(mock_operation, mock_client, "test")
        
        # Assert
        assert result == "sync_test"

    @pytest.mark.asyncio
    async def test_execute_sync_operation_with_non_callable(self):
        """Тест выполнения синхронной операции с не-callable"""
        # Arrange
        mock_client = Mock()
        non_callable_operation = "sync_not_callable"
        
        # Act
        result = self.manager._execute_sync_operation(non_callable_operation, mock_client)
        
        # Assert
        assert result == "sync_not_callable"

    def test_get_client_returns_existing_client(self):
        """Тест получения существующего клиента"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["existing_client"] = mock_client
        
        # Act
        client = self.manager.get_client("existing_client")
        
        # Assert
        assert client == mock_client

    def test_get_client_returns_none_when_not_initialized(self):
        """Тест получения клиента когда не инициализирован"""
        # Act
        client = self.manager.get_client("any_client")
        
        # Assert
        assert client is None

    @pytest.mark.asyncio
    async def test_health_check_with_fresh_status(self):
        """Тест проверки здоровья с свежим статусом"""
        # Arrange
        self.manager._initialized = True
        self.manager._health_status["test_client"] = True
        self.manager._last_health_check["test_client"] = datetime.now()
        
        # Act
        result = self.manager._is_client_healthy("test_client")
        
        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_with_stale_status(self):
        """Тест проверки здоровья с устаревшим статусом"""
        # Arrange
        self.manager._initialized = True
        self.manager._health_status["test_client"] = False
        self.manager._last_health_check["test_client"] = datetime.now() - timedelta(seconds=120)
        
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.return_value.data = []
        self.manager._clients["test_client"] = mock_client
        
        # Act
        result = self.manager._is_client_healthy("test_client")
        
        # Assert
        assert result is True  # Обновленный статус

    @pytest.mark.asyncio
    async def test_health_check_with_no_client(self):
        """Тест проверки здоровья без клиента"""
        # Arrange
        self.manager._initialized = True
        self.manager._clients["test_client"] = None
        
        # Act
        result = self.manager._is_client_healthy("test_client")
        
        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_with_exception(self):
        """Тест проверки здоровья с исключением"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.side_effect = Exception("Health check failed")
        self.manager._clients["test_client"] = mock_client
        
        # Act
        result = self.manager._is_client_healthy("test_client")
        
        # Assert
        assert result is False
        assert self.manager._health_status["test_client"] is False

    def test_get_all_health_status_empty(self):
        """Тест получения статуса всех соединений - пустое"""
        # Arrange
        self.manager._health_status = {}
        
        # Act
        status = self.manager.get_all_health_status()
        
        # Assert
        assert status == {}

    def test_get_all_health_status_with_data(self):
        """Тест получения статуса всех соединений с данными"""
        # Arrange
        self.manager._health_status = {
            "client1": True,
            "client2": False,
            "client3": True
        }
        
        # Act
        status = self.manager.get_all_health_status()
        
        # Assert
        assert status == {
            "client1": True,
            "client2": False,
            "client3": True
        }

    @pytest.mark.asyncio
    async def test_close_clears_clients(self):
        """Тест закрытия очищает клиентов"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["client1"] = mock_client
        self.manager._clients["client2"] = mock_client
        
        # Act
        await self.manager.close()
        
        # Assert
        assert self.manager._initialized is False
        assert self.manager._clients == {}

    @pytest.mark.asyncio
    async def test_close_when_not_initialized(self):
        """Тест закрытия когда не инициализирован"""
        # Act
        await self.manager.close()
        
        # Assert
        assert self.manager._initialized is False

    def test_get_client_count_initialized(self):
        """Тест получения количества клиентов - инициализирован"""
        # Arrange
        self.manager._clients = {
            "client1": Mock(),
            "client2": Mock(),
            "client3": Mock()
        }
        
        # Act
        count = self.manager.get_client_count()
        
        # Assert
        assert count == 3

    def test_get_client_count_not_initialized(self):
        """Тест получения количества клиентов - не инициализирован"""
        # Act
        count = self.manager.get_client_count()
        
        # Assert
        assert count == 0

    def test_is_initialized_true(self):
        """Тест проверки инициализации - истина"""
        # Arrange
        self.manager._initialized = True
        
        # Act
        result = self.manager.is_initialized()
        
        # Assert
        assert result is True

    def test_is_initialized_false(self):
        """Тест проверки инициализации - ложь"""
        # Act
        result = self.manager.is_initialized()
        
        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_concurrent_health_checks(self):
        """Тест конкурентных проверок здоровья"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.return_value.data = []
        self.manager._clients["client1"] = mock_client
        self.manager._clients["client2"] = mock_client
        
        # Act - создаем несколько задач одновременно
        tasks = [
            self.manager._is_client_healthy("client1"),
            self.manager._is_client_healthy("client2"),
            self.manager._is_client_healthy("client1"),
            self.manager._is_client_healthy("client2")
        ]
        results = await asyncio.gather(*tasks)
        
        # Assert
        assert all(result is True for result in results)

    @pytest.mark.asyncio
    async def test_concurrent_execute_operations(self):
        """Тест конкурентных операций выполнения"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        self.manager._clients["default"] = mock_client
        
        def mock_operation(client, index):
            return f"result_{index}"
        
        # Act - создаем несколько задач одновременно
        tasks = [
            self.manager.execute_async(mock_operation, "default", i)
            for i in range(5)
        ]
        results = await asyncio.gather(*tasks)
        
        # Assert
        assert len(results) == 5
        assert all(f"result_{i}" in results for i in range(5))

    @pytest.mark.asyncio
    async def test_health_check_updates_timestamp(self):
        """Тест обновления временной метки при проверке здоровья"""
        # Arrange
        self.manager._initialized = True
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.return_value.data = []
        self.manager._clients["test_client"] = mock_client
        
        old_timestamp = datetime.now() - timedelta(seconds=120)
        self.manager._last_health_check["test_client"] = old_timestamp
        
        # Act
        result = self.manager._is_client_healthy("test_client")
        
        # Assert
        assert result is True
        assert self.manager._last_health_check["test_client"] > old_timestamp

    @pytest.mark.asyncio
    async def test_health_check_preserves_recent_timestamp(self):
        """Тест сохранения недавней временной метки при проверке здоровья"""
        # Arrange
        self.manager._initialized = True
        self.manager._health_status["test_client"] = True
        recent_timestamp = datetime.now() - timedelta(seconds=30)
        self.manager._last_health_check["test_client"] = recent_timestamp
        
        # Act
        result = self.manager._is_client_healthy("test_client")
        
        # Assert
        assert result is True
        assert self.manager._last_health_check["test_client"] == recent_timestamp