#!/usr/bin/env python3
"""
Комплексные тесты для Chat Repository
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from uuid import uuid4, UUID
from backend.repositories.chat_repository import ChatRepository
from backend.core.exceptions import DatabaseError, NotFoundError, ValidationError, ConnectionError, TimeoutError


class TestChatRepository:
    """Тесты для ChatRepository"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.repository = ChatRepository()
        self.mock_supabase = Mock()
        self.mock_response = Mock()
        self.mock_response.data = [{"id": "test_id", "name": "Test Session"}]
        
    def test_init(self):
        """Тест инициализации ChatRepository"""
        assert self.repository._supabase is None
    
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    def test_get_supabase(self, mock_connection_manager):
        """Тест получения Supabase клиента"""
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        
        result = self.repository._get_supabase()
        
        assert result == self.mock_supabase
        assert self.repository._supabase == self.mock_supabase
        mock_connection_manager.get_supabase_client.assert_called_once()
    
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    def test_get_supabase_cached(self, mock_connection_manager):
        """Тест кэширования Supabase клиента"""
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        
        # Первый вызов
        result1 = self.repository._get_supabase()
        
        # Второй вызов - должен использовать кэш
        result2 = self.repository._get_supabase()
        
        assert result1 == result2 == self.mock_supabase
        # Должен быть вызван только один раз
        mock_connection_manager.get_supabase_client.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_session_by_id_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска сессии по ID"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.return_value = self.mock_response
        
        result = await self.repository.find_session_by_id(session_id)
        
        assert result == {"id": "test_id", "name": "Test Session"}
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_session_by_id_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска несуществующей сессии по ID"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_session_by_id(session_id)
        
        assert result is None
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_session_by_id_connection_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки подключения при поиске сессии по ID"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = ConnectionError("Connection failed")
        
        with pytest.raises(DatabaseError, match="Database connection failed"):
            await self.repository.find_session_by_id(session_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_session_by_id_timeout_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки таймаута при поиске сессии по ID"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = TimeoutError("Operation timed out")
        
        with pytest.raises(DatabaseError, match="Database operation timed out"):
            await self.repository.find_session_by_id(session_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_session_by_id_generic_error(self, mock_connection_manager, mock_execute_operation):
        """Тест общей ошибки при поиске сессии по ID"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Generic error")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_session_by_id(session_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_sessions_by_project_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска сессий по проекту"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "session1"}, {"id": "session2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_sessions_by_project(project_id, limit=20, offset=10)
        
        assert len(result) == 2
        assert result[0]["id"] == "session1"
        assert result[1]["id"] == "session2"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_save_session_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного сохранения сессии"""
        session_data = {"name": "Test Session", "project_id": str(uuid4())}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "new_session_id", **session_data}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.save_session(session_data)
        
        assert result["id"] == "new_session_id"
        assert result["name"] == "Test Session"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_save_session_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при сохранении сессии"""
        session_data = {"name": "Test Session"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Save failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.save_session(session_data)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_messages_by_session_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска сообщений по сессии"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [
            {"id": "msg1", "content": "Hello"},
            {"id": "msg2", "content": "World"}
        ]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_messages_by_session(session_id, limit=100, offset=0)
        
        assert len(result) == 2
        assert result[0]["content"] == "Hello"
        assert result[1]["content"] == "World"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_save_message_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного сохранения сообщения"""
        message_data = {"session_id": str(uuid4()), "content": "Test message", "role": "user"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "new_message_id", **message_data}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.save_message(message_data)
        
        assert result["id"] == "new_message_id"
        assert result["content"] == "Test message"
        assert result["role"] == "user"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_save_message_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при сохранении сообщения"""
        message_data = {"content": "Test message"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Save failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.save_message(message_data)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_sessions_by_user_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска сессий по пользователю"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "session1"}, {"id": "session2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_sessions_by_user(user_id, limit=30, offset=5)
        
        assert len(result) == 2
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_recent_sessions_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска недавних сессий"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "recent1"}, {"id": "recent2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_recent_sessions(user_id, limit=3)
        
        assert len(result) == 2
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_update_session_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного обновления сессии"""
        session_id = uuid4()
        session_data = {"name": "Updated Session"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(session_id), **session_data}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.update_session(session_id, session_data)
        
        assert result["id"] == str(session_id)
        assert result["name"] == "Updated Session"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_update_session_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при обновлении сессии"""
        session_id = uuid4()
        session_data = {"name": "Updated Session"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Update failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.update_session(session_id, session_data)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_delete_session_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного удаления сессии"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(session_id)}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.delete_session(session_id)
        
        assert result is True
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_delete_session_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест удаления несуществующей сессии"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.delete_session(session_id)
        
        assert result is False
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_delete_session_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при удалении сессии"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Delete failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.delete_session(session_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_count_messages_by_session_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного подсчета сообщений в сессии"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.count = 42
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.count_messages_by_session(session_id)
        
        assert result == 42
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_count_messages_by_session_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при подсчете сообщений в сессии"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Count failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.count_messages_by_session(session_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_sessions_by_project_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска сессий по проекту с параметрами по умолчанию"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_sessions_by_project(project_id)
        
        assert result == []
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_messages_by_session_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска сообщений по сессии с параметрами по умолчанию"""
        session_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_messages_by_session(session_id)
        
        assert result == []
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_sessions_by_user_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска сессий по пользователю с параметрами по умолчанию"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_sessions_by_user(user_id)
        
        assert result == []
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.chat_repository.execute_supabase_operation')
    @patch('backend.repositories.chat_repository.connection_pool_manager')
    async def test_find_recent_sessions_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска недавних сессий с параметрами по умолчанию"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_recent_sessions(user_id)
        
        assert result == []
        mock_execute_operation.assert_called_once()