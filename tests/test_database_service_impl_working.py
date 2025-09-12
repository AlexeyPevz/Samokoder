#!/usr/bin/env python3
"""
Рабочие тесты для Database Service Implementation - исправленные тесты
"""

import pytest
from uuid import uuid4
from unittest.mock import Mock, patch, AsyncMock
from backend.services.implementations.database_service_impl import DatabaseServiceImpl


class TestDatabaseServiceImpl:
    """Рабочие тесты для DatabaseServiceImpl"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.service = DatabaseServiceImpl()
    
    def test_init(self):
        """Тест инициализации сервиса"""
        assert self.service._supabase is None
    
    @patch('backend.services.implementations.database_service_impl.connection_pool_manager')
    def test_get_supabase_success(self, mock_connection_manager):
        """Тест получения Supabase клиента - успех"""
        mock_client = Mock()
        mock_connection_manager.get_supabase_client.return_value = mock_client
        
        result = self.service._get_supabase()
        
        assert result == mock_client
        assert self.service._supabase == mock_client
        mock_connection_manager.get_supabase_client.assert_called_once()
    
    @patch('backend.services.implementations.database_service_impl.connection_pool_manager')
    def test_get_supabase_cached(self, mock_connection_manager):
        """Тест получения кэшированного Supabase клиента"""
        mock_client = Mock()
        self.service._supabase = mock_client
        
        result = self.service._get_supabase()
        
        assert result == mock_client
        mock_connection_manager.get_supabase_client.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_get_user_success(self):
        """Тест получения пользователя - успех"""
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id), "name": "Test User"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_user(user_id)
        
        assert result == {"id": str(user_id), "name": "Test User"}
        mock_supabase.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_get_user_no_data(self):
        """Тест получения пользователя без данных"""
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = None
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_user(user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_error(self):
        """Тест получения пользователя с ошибкой"""
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.get_user(user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_create_user_success(self):
        """Тест создания пользователя - успех"""
        user_data = {"name": "Test User", "email": "test@example.com"}
        mock_supabase = Mock()
        mock_response = Mock()
        test_id = str(uuid4())
        mock_response.data = [{"id": test_id, "name": "Test User"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.create_user(user_data)
        
        assert result == {"id": test_id, "name": "Test User"}
        mock_supabase.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_create_user_error(self):
        """Тест создания пользователя с ошибкой"""
        user_data = {"name": "Test User", "email": "test@example.com"}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.create_user(user_data)
    
    @pytest.mark.asyncio
    async def test_update_user_success(self):
        """Тест обновления пользователя - успех"""
        user_id = uuid4()
        user_data = {"name": "Updated User"}
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id), "name": "Updated User"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.update_user(user_id, user_data)
        
        assert result == {"id": str(user_id), "name": "Updated User"}
        mock_supabase.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_update_user_error(self):
        """Тест обновления пользователя с ошибкой"""
        user_id = uuid4()
        user_data = {"name": "Updated User"}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.update_user(user_id, user_data)
    
    @pytest.mark.asyncio
    async def test_delete_user_success(self):
        """Тест удаления пользователя - успех"""
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id)}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.delete_user(user_id)
        
        assert result == True
        mock_supabase.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_delete_user_error(self):
        """Тест удаления пользователя с ошибкой"""
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.delete_user(user_id)
        
        assert result == False
    
    @pytest.mark.asyncio
    async def test_get_project_success(self):
        """Тест получения проекта - успех"""
        project_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(project_id), "name": "Test Project"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_project(project_id, user_id)
        
        assert result == {"id": str(project_id), "name": "Test Project"}
        mock_supabase.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_get_project_no_data(self):
        """Тест получения проекта без данных"""
        project_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = None
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_project(project_id, user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_project_error(self):
        """Тест получения проекта с ошибкой"""
        project_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.get_project(project_id, user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_create_project_success(self):
        """Тест создания проекта - успех"""
        project_data = {"name": "Test Project", "description": "Test Description"}
        mock_supabase = Mock()
        mock_response = Mock()
        test_id = str(uuid4())
        mock_response.data = [{"id": test_id, "name": "Test Project"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.create_project(project_data)
        
        assert result == {"id": test_id, "name": "Test Project"}
        mock_supabase.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_create_project_error(self):
        """Тест создания проекта с ошибкой"""
        project_data = {"name": "Test Project", "description": "Test Description"}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.create_project(project_data)
    
    @pytest.mark.asyncio
    async def test_update_project_success(self):
        """Тест обновления проекта - успех"""
        project_id = uuid4()
        project_data = {"name": "Updated Project"}
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(project_id), "name": "Updated Project"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.update_project(project_id, project_data)
        
        assert result == {"id": str(project_id), "name": "Updated Project"}
        mock_supabase.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_update_project_error(self):
        """Тест обновления проекта с ошибкой"""
        project_id = uuid4()
        project_data = {"name": "Updated Project"}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.update_project(project_id, project_data)
    
    @pytest.mark.asyncio
    async def test_delete_project_success(self):
        """Тест удаления проекта - успех"""
        project_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(project_id)}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.delete_project(project_id, user_id)
        
        assert result == True
        mock_supabase.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_delete_project_error(self):
        """Тест удаления проекта с ошибкой"""
        project_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.delete_project(project_id, user_id)
        
        assert result == False
    
    @pytest.mark.asyncio
    async def test_list_projects_success(self):
        """Тест получения списка проектов - успех"""
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [
            {"id": str(uuid4()), "name": "Project 1"},
            {"id": str(uuid4()), "name": "Project 2"}
        ]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.list_projects(user_id)
        
        assert len(result) == 2
        assert result[0]["name"] == "Project 1"
        assert result[1]["name"] == "Project 2"
        mock_supabase.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_list_projects_error(self):
        """Тест получения списка проектов с ошибкой"""
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.list_projects(user_id)
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_chat_session_success(self):
        """Тест получения сессии чата - успех"""
        session_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(session_id), "title": "Test Session"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_chat_session(session_id, user_id)
        
        assert result == {"id": str(session_id), "title": "Test Session"}
        mock_supabase.table.assert_called_once_with("chat_sessions")
    
    @pytest.mark.asyncio
    async def test_get_chat_session_no_data(self):
        """Тест получения сессии чата без данных"""
        session_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = None
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_chat_session(session_id, user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_chat_session_error(self):
        """Тест получения сессии чата с ошибкой"""
        session_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.get_chat_session(session_id, user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_create_chat_session_success(self):
        """Тест создания сессии чата - успех"""
        session_data = {"title": "Test Session", "user_id": str(uuid4())}
        mock_supabase = Mock()
        mock_response = Mock()
        test_id = str(uuid4())
        mock_response.data = [{"id": test_id, "title": "Test Session"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.create_chat_session(session_data)
        
        assert result == {"id": test_id, "title": "Test Session"}
        mock_supabase.table.assert_called_once_with("chat_sessions")
    
    @pytest.mark.asyncio
    async def test_create_chat_session_error(self):
        """Тест создания сессии чата с ошибкой"""
        session_data = {"title": "Test Session", "user_id": str(uuid4())}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.create_chat_session(session_data)
    
    @pytest.mark.asyncio
    async def test_get_chat_messages_success(self):
        """Тест получения сообщений чата - успех"""
        session_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [
            {"id": str(uuid4()), "content": "Message 1"},
            {"id": str(uuid4()), "content": "Message 2"}
        ]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_chat_messages(session_id, user_id)
        
        assert len(result) == 2
        assert result[0]["content"] == "Message 1"
        assert result[1]["content"] == "Message 2"
        mock_supabase.table.assert_called_once_with("chat_messages")
    
    @pytest.mark.asyncio
    async def test_get_chat_messages_error(self):
        """Тест получения сообщений чата с ошибкой"""
        session_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.get_chat_messages(session_id, user_id)
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_create_chat_message_success(self):
        """Тест создания сообщения чата - успех"""
        message_data = {"content": "Test Message", "session_id": str(uuid4())}
        mock_supabase = Mock()
        mock_response = Mock()
        test_id = str(uuid4())
        mock_response.data = [{"id": test_id, "content": "Test Message"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.create_chat_message(message_data)
        
        assert result == {"id": test_id, "content": "Test Message"}
        mock_supabase.table.assert_called_once_with("chat_messages")
    
    @pytest.mark.asyncio
    async def test_create_chat_message_error(self):
        """Тест создания сообщения чата с ошибкой"""
        message_data = {"content": "Test Message", "session_id": str(uuid4())}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.create_chat_message(message_data)
    
    @pytest.mark.asyncio
    async def test_get_api_key_success(self):
        """Тест получения API ключа - успех"""
        key_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(key_id), "name": "Test Key"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_api_key(key_id, user_id)
        
        assert result == {"id": str(key_id), "name": "Test Key"}
        mock_supabase.table.assert_called_once_with("api_keys")
    
    @pytest.mark.asyncio
    async def test_get_api_key_no_data(self):
        """Тест получения API ключа без данных"""
        key_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = None
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_api_key(key_id, user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_api_key_error(self):
        """Тест получения API ключа с ошибкой"""
        key_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.get_api_key(key_id, user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_create_api_key_success(self):
        """Тест создания API ключа - успех"""
        key_data = {"name": "Test Key", "user_id": str(uuid4())}
        mock_supabase = Mock()
        mock_response = Mock()
        test_id = str(uuid4())
        mock_response.data = [{"id": test_id, "name": "Test Key"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.create_api_key(key_data)
        
        assert result == {"id": test_id, "name": "Test Key"}
        mock_supabase.table.assert_called_once_with("api_keys")
    
    @pytest.mark.asyncio
    async def test_create_api_key_error(self):
        """Тест создания API ключа с ошибкой"""
        key_data = {"name": "Test Key", "user_id": str(uuid4())}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.create_api_key(key_data)
    
    @pytest.mark.asyncio
    async def test_update_api_key_success(self):
        """Тест обновления API ключа - успех"""
        key_id = uuid4()
        key_data = {"name": "Updated Key"}
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(key_id), "name": "Updated Key"}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.update_api_key(key_id, key_data)
        
        assert result == {"id": str(key_id), "name": "Updated Key"}
        mock_supabase.table.assert_called_once_with("api_keys")
    
    @pytest.mark.asyncio
    async def test_update_api_key_error(self):
        """Тест обновления API ключа с ошибкой"""
        key_id = uuid4()
        key_data = {"name": "Updated Key"}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.update_api_key(key_id, key_data)
    
    @pytest.mark.asyncio
    async def test_delete_api_key_success(self):
        """Тест удаления API ключа - успех"""
        key_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": str(key_id)}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.delete_api_key(key_id, user_id)
        
        assert result == True
        mock_supabase.table.assert_called_once_with("api_keys")
    
    @pytest.mark.asyncio
    async def test_delete_api_key_error(self):
        """Тест удаления API ключа с ошибкой"""
        key_id = uuid4()
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.delete_api_key(key_id, user_id)
        
        assert result == False
    
    @pytest.mark.asyncio
    async def test_list_api_keys_success(self):
        """Тест получения списка API ключей - успех"""
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [
            {"id": str(uuid4()), "name": "Key 1"},
            {"id": str(uuid4()), "name": "Key 2"}
        ]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.list_api_keys(user_id)
        
        assert len(result) == 2
        assert result[0]["name"] == "Key 1"
        assert result[1]["name"] == "Key 2"
        mock_supabase.table.assert_called_once_with("api_keys")
    
    @pytest.mark.asyncio
    async def test_list_api_keys_error(self):
        """Тест получения списка API ключей с ошибкой"""
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.list_api_keys(user_id)
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_ai_usage_success(self):
        """Тест получения AI использования - успех"""
        user_id = uuid4()
        mock_supabase = Mock()
        mock_response = Mock()
        mock_response.data = [
            {"id": str(uuid4()), "tokens": 100},
            {"id": str(uuid4()), "tokens": 200}
        ]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.get_ai_usage(user_id)
        
        assert len(result) == 2
        assert result[0]["tokens"] == 100
        assert result[1]["tokens"] == 200
        mock_supabase.table.assert_called_once_with("ai_usage")
    
    @pytest.mark.asyncio
    async def test_get_ai_usage_error(self):
        """Тест получения AI использования с ошибкой"""
        user_id = uuid4()
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            result = await self.service.get_ai_usage(user_id)
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_create_ai_usage_success(self):
        """Тест создания AI использования - успех"""
        usage_data = {"tokens": 100, "user_id": str(uuid4())}
        mock_supabase = Mock()
        mock_response = Mock()
        test_id = str(uuid4())
        mock_response.data = [{"id": test_id, "tokens": 100}]
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', return_value=mock_response):
            result = await self.service.create_ai_usage(usage_data)
        
        assert result == {"id": test_id, "tokens": 100}
        mock_supabase.table.assert_called_once_with("ai_usage")
    
    @pytest.mark.asyncio
    async def test_create_ai_usage_error(self):
        """Тест создания AI использования с ошибкой"""
        usage_data = {"tokens": 100, "user_id": str(uuid4())}
        mock_supabase = Mock()
        
        with patch.object(self.service, '_get_supabase', return_value=mock_supabase), \
             patch('backend.services.implementations.database_service_impl.execute_supabase_operation', side_effect=Exception("Database error")):
            with pytest.raises(Exception, match="Database error"):
                await self.service.create_ai_usage(usage_data)