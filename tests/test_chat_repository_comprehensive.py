"""
Комплексные тесты для ChatRepository (13% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime, timezone

from backend.repositories.chat_repository import ChatRepository
from backend.core.exceptions import DatabaseError, NotFoundError, ValidationError, ConnectionError, TimeoutError


class TestChatRepository:
    """Тесты для ChatRepository"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.repository = ChatRepository()
        self.mock_supabase = AsyncMock()
        self.mock_response = Mock()
        self.mock_response.data = [{"id": "123", "title": "Test Chat"}]

    @patch('backend.repositories.chat_repository.connection_pool_manager')
    def test_init(self, mock_pool_manager):
        """Тест инициализации ChatRepository"""
        repository = ChatRepository()
        assert repository._supabase is None
        assert hasattr(repository, '_get_supabase')

    @patch('backend.repositories.chat_repository.connection_pool_manager')
    def test_get_supabase_initial(self, mock_pool_manager):
        """Тест получения Supabase клиента при первом вызове"""
        mock_client = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_client
        
        repository = ChatRepository()
        result = repository._get_supabase()
        
        assert result == mock_client
        assert repository._supabase == mock_client
        mock_pool_manager.get_supabase_client.assert_called_once()

    @patch('backend.repositories.chat_repository.connection_pool_manager')
    def test_get_supabase_cached(self, mock_pool_manager):
        """Тест получения кэшированного Supabase клиента"""
        mock_client = Mock()
        repository = ChatRepository()
        repository._supabase = mock_client
        
        result = repository._get_supabase()
        
        assert result == mock_client
        mock_pool_manager.get_supabase_client.assert_not_called()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_session_by_id_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска сессии по ID"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.return_value = self.mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.find_session_by_id(session_id)
        
        # Assert
        assert result == self.mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_session_by_id_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска несуществующей сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.find_session_by_id(session_id)
        
        # Assert
        assert result is None

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_session_by_id_connection_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ConnectionError при поиске сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ConnectionError("Connection failed")
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_session_by_id(session_id)
        assert "Database connection failed" in str(exc_info.value)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_session_by_id_timeout_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки TimeoutError при поиске сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = TimeoutError("Timeout")
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_session_by_id(session_id)
        assert "Database operation timed out" in str(exc_info.value)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_session_by_id_general_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки общего исключения при поиске сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("General error")
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_session_by_id(session_id)
        assert "Database operation failed" in str(exc_info.value)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_sessions_by_project_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска сессий по проекту"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [
            {"id": "123", "title": "Chat 1"},
            {"id": "124", "title": "Chat 2"}
        ]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"project_id": "project_id"}
        
        # Act
        result = await self.repository.find_sessions_by_project(project_id, limit=10, offset=0)
        
        # Assert
        assert len(result) == 2
        assert result[0]["title"] == "Chat 1"
        assert result[1]["title"] == "Chat 2"
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_sessions_by_project_empty(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска сессий по проекту - пустой результат"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"project_id": "project_id"}
        
        # Act
        result = await self.repository.find_sessions_by_project(project_id)
        
        # Assert
        assert result == []

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_sessions_by_project_with_pagination(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска сессий по проекту с пагинацией"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "123", "title": "Chat 1"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"project_id": "project_id"}
        
        # Act
        result = await self.repository.find_sessions_by_project(project_id, limit=5, offset=10)
        
        # Assert
        assert len(result) == 1
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_sessions_by_project_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при поиске сессий по проекту"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("Database error")
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"project_id": "project_id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError):
            await self.repository.find_sessions_by_project(project_id)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_sessions_by_user_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска сессий по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "123", "title": "User Chat"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act
        result = await self.repository.find_sessions_by_user(user_id, limit=10, offset=0)
        
        # Assert
        assert len(result) == 1
        assert result[0]["title"] == "User Chat"
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_sessions_by_user_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при поиске сессий по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ConnectionError("Connection failed")
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_sessions_by_user(user_id)
        assert "Database connection failed" in str(exc_info.value)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_create_session_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного создания сессии"""
        # Arrange
        session_data = {
            "id": str(uuid4()),
            "project_id": str(uuid4()),
            "user_id": str(uuid4()),
            "title": "New Chat"
        }
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [session_data]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        
        # Act
        result = await self.repository.create_session(session_data)
        
        # Assert
        assert result == session_data
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_create_session_validation_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ValidationError при создании сессии"""
        # Arrange
        session_data = {"title": "New Chat"}  # Неполные данные
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ValidationError("Validation failed")
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.create_session(session_data)
        assert "Database operation failed" in str(exc_info.value)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_update_session_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного обновления сессии"""
        # Arrange
        session_id = uuid4()
        update_data = {"title": "Updated Chat"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(session_id), "title": "Updated Chat"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.update_session(session_id, update_data)
        
        # Assert
        assert result == mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_update_session_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обновления несуществующей сессии"""
        # Arrange
        session_id = uuid4()
        update_data = {"title": "Updated Chat"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.update_session(session_id, update_data)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_delete_session_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного удаления сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(session_id)}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.delete_session(session_id)
        
        # Assert
        assert result is True
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_delete_session_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест удаления несуществующей сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.delete_session(session_id)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_messages_by_session_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска сообщений по сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [
            {"id": "123", "role": "user", "content": "Hello"},
            {"id": "124", "role": "assistant", "content": "Hi there"}
        ]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"session_id": "session_id"}
        
        # Act
        result = await self.repository.find_messages_by_session(session_id, limit=10, offset=0)
        
        # Assert
        assert len(result) == 2
        assert result[0]["role"] == "user"
        assert result[1]["role"] == "assistant"
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_messages_by_session_empty(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска сообщений по сессии - пустой результат"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"session_id": "session_id"}
        
        # Act
        result = await self.repository.find_messages_by_session(session_id)
        
        # Assert
        assert result == []

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_find_messages_by_session_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при поиске сообщений по сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("Database error")
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"session_id": "session_id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError):
            await self.repository.find_messages_by_session(session_id)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_create_message_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного создания сообщения"""
        # Arrange
        message_data = {
            "id": str(uuid4()),
            "session_id": str(uuid4()),
            "role": "user",
            "content": "Hello, world!"
        }
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [message_data]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        
        # Act
        result = await self.repository.create_message(message_data)
        
        # Assert
        assert result == message_data
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_create_message_validation_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ValidationError при создании сообщения"""
        # Arrange
        message_data = {"content": "Hello"}  # Неполные данные
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ValidationError("Validation failed")
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.create_message(message_data)
        assert "Database operation failed" in str(exc_info.value)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_update_message_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного обновления сообщения"""
        # Arrange
        message_id = uuid4()
        update_data = {"content": "Updated message"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(message_id), "content": "Updated message"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.update_message(message_id, update_data)
        
        # Assert
        assert result == mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_update_message_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обновления несуществующего сообщения"""
        # Arrange
        message_id = uuid4()
        update_data = {"content": "Updated message"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.update_message(message_id, update_data)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_delete_message_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного удаления сообщения"""
        # Arrange
        message_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(message_id)}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.delete_message(message_id)
        
        # Assert
        assert result is True
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_delete_message_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест удаления несуществующего сообщения"""
        # Arrange
        message_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.delete_message(message_id)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_count_sessions_by_project_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного подсчета сессий по проекту"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.count = 5
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.COLUMNS = {"project_id": "project_id"}
        
        # Act
        result = await self.repository.count_sessions_by_project(project_id)
        
        # Assert
        assert result == 5
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_count_sessions_by_project_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при подсчете сессий по проекту"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("Database error")
        mock_db_config.TABLES = {"chat_sessions": "chat_sessions"}
        mock_db_config.COLUMNS = {"project_id": "project_id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError):
            await self.repository.count_sessions_by_project(project_id)

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_count_messages_by_session_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного подсчета сообщений по сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.count = 10
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.COLUMNS = {"session_id": "session_id"}
        
        # Act
        result = await self.repository.count_messages_by_session(session_id)
        
        # Assert
        assert result == 10
        mock_execute.assert_called_once()

    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    @patch('backend.repositories.chat_repository.db_config')
    async def test_count_messages_by_session_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при подсчете сообщений по сессии"""
        # Arrange
        session_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = TimeoutError("Timeout")
        mock_db_config.TABLES = {"chat_messages": "chat_messages"}
        mock_db_config.COLUMNS = {"session_id": "session_id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.count_messages_by_session(session_id)
        assert "Database operation timed out" in str(exc_info.value)