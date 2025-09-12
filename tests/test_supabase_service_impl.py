#!/usr/bin/env python3
"""
Тесты для Supabase Service Implementation
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from backend.services.implementations.supabase_service_impl import SupabaseServiceImpl


class TestSupabaseServiceImpl:
    """Тесты для SupabaseServiceImpl"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.service = SupabaseServiceImpl()
    
    def test_init(self):
        """Тест инициализации сервиса"""
        assert self.service.client is None
    
    @patch('backend.services.implementations.supabase_service_impl.connection_manager')
    def test_get_client_success(self, mock_connection_manager):
        """Тест получения клиента - успех"""
        mock_client = Mock()
        mock_connection_manager.get_pool.return_value = mock_client
        
        result = self.service._get_client()
        
        assert result == mock_client
        assert self.service.client == mock_client
        mock_connection_manager.get_pool.assert_called_once_with('supabase')
    
    @patch('backend.services.implementations.supabase_service_impl.connection_manager')
    def test_get_client_error(self, mock_connection_manager):
        """Тест получения клиента с ошибкой"""
        mock_connection_manager.get_pool.side_effect = Exception("Connection failed")
        
        result = self.service._get_client()
        
        assert result is None
        assert self.service.client is None
    
    @patch('backend.services.implementations.supabase_service_impl.connection_manager')
    def test_get_client_cached(self, mock_connection_manager):
        """Тест получения кэшированного клиента"""
        mock_client = Mock()
        self.service.client = mock_client
        
        result = self.service._get_client()
        
        assert result == mock_client
        mock_connection_manager.get_pool.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_get_user_success(self):
        """Тест получения пользователя - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = {"id": "user123", "name": "Test User"}
        mock_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_user("user123")
        
        assert result == {"id": "user123", "name": "Test User"}
        mock_client.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_get_user_no_client(self):
        """Тест получения пользователя без клиента"""
        with patch.object(self.service, '_get_client', return_value=None):
            result = await self.service.get_user("user123")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_error(self):
        """Тест получения пользователя с ошибкой"""
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.side_effect = Exception("Database error")
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_user("user123")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_no_data(self):
        """Тест получения пользователя без данных"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = None
        mock_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_user("user123")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_create_user_success(self):
        """Тест создания пользователя - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": "user123", "name": "Test User"}]
        mock_client.table.return_value.insert.return_value.execute.return_value = mock_response
        
        user_data = {"name": "Test User", "email": "test@example.com"}
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.create_user(user_data)
        
        assert result == {"id": "user123", "name": "Test User"}
        mock_client.table.assert_called_once_with("profiles")
        mock_client.table.return_value.insert.assert_called_once_with(user_data)
    
    @pytest.mark.asyncio
    async def test_create_user_no_client(self):
        """Тест создания пользователя без клиента"""
        user_data = {"name": "Test User", "email": "test@example.com"}
        
        with patch.object(self.service, '_get_client', return_value=None):
            with pytest.raises(RuntimeError, match="Supabase not available"):
                await self.service.create_user(user_data)
    
    @pytest.mark.asyncio
    async def test_create_user_error(self):
        """Тест создания пользователя с ошибкой"""
        mock_client = Mock()
        mock_client.table.return_value.insert.return_value.execute.side_effect = Exception("Database error")
        
        user_data = {"name": "Test User", "email": "test@example.com"}
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.create_user(user_data)
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_create_user_no_data(self):
        """Тест создания пользователя без данных"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = None
        mock_client.table.return_value.insert.return_value.execute.return_value = mock_response
        
        user_data = {"name": "Test User", "email": "test@example.com"}
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.create_user(user_data)
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_update_user_success(self):
        """Тест обновления пользователя - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": "user123", "name": "Updated User"}]
        mock_client.table.return_value.update.return_value.eq.return_value.execute.return_value = mock_response
        
        user_data = {"name": "Updated User"}
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.update_user("user123", user_data)
        
        assert result == {"id": "user123", "name": "Updated User"}
        mock_client.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_update_user_no_client(self):
        """Тест обновления пользователя без клиента"""
        user_data = {"name": "Updated User"}
        
        with patch.object(self.service, '_get_client', return_value=None):
            with pytest.raises(RuntimeError, match="Supabase not available"):
                await self.service.update_user("user123", user_data)
    
    @pytest.mark.asyncio
    async def test_update_user_error(self):
        """Тест обновления пользователя с ошибкой"""
        mock_client = Mock()
        mock_client.table.return_value.update.return_value.eq.return_value.execute.side_effect = Exception("Database error")
        
        user_data = {"name": "Updated User"}
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.update_user("user123", user_data)
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_delete_user_success(self):
        """Тест удаления пользователя - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": "user123"}]
        mock_client.table.return_value.delete.return_value.eq.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.delete_user("user123")
        
        assert result == {"id": "user123"}
        mock_client.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_delete_user_no_client(self):
        """Тест удаления пользователя без клиента"""
        with patch.object(self.service, '_get_client', return_value=None):
            with pytest.raises(RuntimeError, match="Supabase not available"):
                await self.service.delete_user("user123")
    
    @pytest.mark.asyncio
    async def test_delete_user_error(self):
        """Тест удаления пользователя с ошибкой"""
        mock_client = Mock()
        mock_client.table.return_value.delete.return_value.eq.return_value.execute.side_effect = Exception("Database error")
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.delete_user("user123")
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_get_users_success(self):
        """Тест получения списка пользователей - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [
            {"id": "user1", "name": "User 1"},
            {"id": "user2", "name": "User 2"}
        ]
        mock_client.table.return_value.select.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_users()
        
        assert result == [
            {"id": "user1", "name": "User 1"},
            {"id": "user2", "name": "User 2"}
        ]
        mock_client.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_get_users_no_client(self):
        """Тест получения списка пользователей без клиента"""
        with patch.object(self.service, '_get_client', return_value=None):
            result = await self.service.get_users()
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_users_error(self):
        """Тест получения списка пользователей с ошибкой"""
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.execute.side_effect = Exception("Database error")
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_users()
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_users_no_data(self):
        """Тест получения списка пользователей без данных"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = None
        mock_client.table.return_value.select.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_users()
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_project_success(self):
        """Тест получения проекта - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = {"id": "project123", "name": "Test Project"}
        mock_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_project("project123")
        
        assert result == {"id": "project123", "name": "Test Project"}
        mock_client.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_get_project_no_client(self):
        """Тест получения проекта без клиента"""
        with patch.object(self.service, '_get_client', return_value=None):
            result = await self.service.get_project("project123")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_project_error(self):
        """Тест получения проекта с ошибкой"""
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.side_effect = Exception("Database error")
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_project("project123")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_create_project_success(self):
        """Тест создания проекта - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": "project123", "name": "Test Project"}]
        mock_client.table.return_value.insert.return_value.execute.return_value = mock_response
        
        project_data = {"name": "Test Project", "description": "Test Description"}
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.create_project(project_data)
        
        assert result == {"id": "project123", "name": "Test Project"}
        mock_client.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_create_project_no_client(self):
        """Тест создания проекта без клиента"""
        project_data = {"name": "Test Project", "description": "Test Description"}
        
        with patch.object(self.service, '_get_client', return_value=None):
            with pytest.raises(RuntimeError, match="Supabase not available"):
                await self.service.create_project(project_data)
    
    @pytest.mark.asyncio
    async def test_update_project_success(self):
        """Тест обновления проекта - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": "project123", "name": "Updated Project"}]
        mock_client.table.return_value.update.return_value.eq.return_value.execute.return_value = mock_response
        
        project_data = {"name": "Updated Project"}
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.update_project("project123", project_data)
        
        assert result == {"id": "project123", "name": "Updated Project"}
        mock_client.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_delete_project_success(self):
        """Тест удаления проекта - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": "project123"}]
        mock_client.table.return_value.delete.return_value.eq.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.delete_project("project123")
        
        assert result == {"id": "project123"}
        mock_client.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_get_projects_success(self):
        """Тест получения списка проектов - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [
            {"id": "project1", "name": "Project 1"},
            {"id": "project2", "name": "Project 2"}
        ]
        mock_client.table.return_value.select.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.get_projects()
        
        assert result == [
            {"id": "project1", "name": "Project 1"},
            {"id": "project2", "name": "Project 2"}
        ]
        mock_client.table.assert_called_once_with("projects")
    
    @pytest.mark.asyncio
    async def test_get_projects_no_client(self):
        """Тест получения списка проектов без клиента"""
        with patch.object(self.service, '_get_client', return_value=None):
            result = await self.service.get_projects()
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Тест проверки здоровья - успех"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.data = [{"id": "test"}]
        mock_client.table.return_value.select.return_value.limit.return_value.execute.return_value = mock_response
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.health_check()
        
        assert result == {"status": "healthy", "service": "supabase"}
        mock_client.table.assert_called_once_with("profiles")
    
    @pytest.mark.asyncio
    async def test_health_check_no_client(self):
        """Тест проверки здоровья без клиента"""
        with patch.object(self.service, '_get_client', return_value=None):
            result = await self.service.health_check()
        
        assert result == {"status": "unhealthy", "service": "supabase", "error": "No client available"}
    
    @pytest.mark.asyncio
    async def test_health_check_error(self):
        """Тест проверки здоровья с ошибкой"""
        mock_client = Mock()
        mock_client.table.return_value.select.return_value.limit.return_value.execute.side_effect = Exception("Database error")
        
        with patch.object(self.service, '_get_client', return_value=mock_client):
            result = await self.service.health_check()
        
        assert result == {"status": "unhealthy", "service": "supabase", "error": "Database error"}