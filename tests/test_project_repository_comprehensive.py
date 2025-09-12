#!/usr/bin/env python3
"""
Комплексные тесты для Project Repository
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from uuid import uuid4, UUID
from backend.repositories.project_repository import ProjectRepository
from backend.core.exceptions import DatabaseError, NotFoundError, ValidationError, ConnectionError, TimeoutError, ProjectError


class TestProjectRepository:
    """Тесты для ProjectRepository"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.repository = ProjectRepository()
        self.mock_supabase = Mock()
        self.mock_response = Mock()
        self.mock_response.data = [{"id": "test_id", "name": "Test Project"}]
        
    def test_init(self):
        """Тест инициализации ProjectRepository"""
        assert self.repository._supabase is None
    
    @patch('backend.repositories.project_repository.connection_pool_manager')
    def test_get_supabase(self, mock_connection_manager):
        """Тест получения Supabase клиента"""
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        
        result = self.repository._get_supabase()
        
        assert result == self.mock_supabase
        assert self.repository._supabase == self.mock_supabase
        mock_connection_manager.get_supabase_client.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_id_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска проекта по ID"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.return_value = self.mock_response
        
        result = await self.repository.find_by_id(project_id)
        
        assert result == {"id": "test_id", "name": "Test Project"}
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_id_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска несуществующего проекта по ID"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_id(project_id)
        
        assert result is None
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_id_connection_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки подключения при поиске проекта по ID"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = ConnectionError("Connection failed")
        
        with pytest.raises(DatabaseError, match="Database connection failed"):
            await self.repository.find_by_id(project_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_id_timeout_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки таймаута при поиске проекта по ID"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = TimeoutError("Operation timed out")
        
        with pytest.raises(DatabaseError, match="Database operation timed out"):
            await self.repository.find_by_id(project_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_id_generic_error(self, mock_connection_manager, mock_execute_operation):
        """Тест общей ошибки при поиске проекта по ID"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Generic error")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_by_id(project_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_user_id_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска проектов по ID пользователя"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "project1"}, {"id": "project2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_user_id(user_id, limit=20, offset=10)
        
        assert len(result) == 2
        assert result[0]["id"] == "project1"
        assert result[1]["id"] == "project2"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_user_id_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска проектов по ID пользователя с параметрами по умолчанию"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_user_id(user_id)
        
        assert result == []
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_save_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного сохранения проекта"""
        project_data = {"name": "New Project", "user_id": str(uuid4())}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "new_project_id", **project_data}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.save(project_data)
        
        assert result["id"] == "new_project_id"
        assert result["name"] == "New Project"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_save_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при сохранении проекта"""
        project_data = {"name": "New Project"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Save failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.save(project_data)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_update_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного обновления проекта"""
        project_id = uuid4()
        project_data = {"name": "Updated Project"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(project_id), **project_data}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.update(project_id, project_data)
        
        assert result["id"] == str(project_id)
        assert result["name"] == "Updated Project"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_update_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при обновлении проекта"""
        project_id = uuid4()
        project_data = {"name": "Updated Project"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Update failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.update(project_id, project_data)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_delete_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного удаления проекта"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(project_id)}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.delete(project_id)
        
        assert result is True
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_delete_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест удаления несуществующего проекта"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.delete(project_id)
        
        assert result is False
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_delete_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при удалении проекта"""
        project_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Delete failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.delete(project_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_name_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска проекта по имени"""
        user_id = uuid4()
        project_name = "Test Project"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "project_id", "name": project_name}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_name(user_id, project_name)
        
        assert result["id"] == "project_id"
        assert result["name"] == project_name
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_name_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска несуществующего проекта по имени"""
        user_id = uuid4()
        project_name = "Non-existent Project"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_name(user_id, project_name)
        
        assert result is None
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_recent_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска недавних проектов"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "recent1"}, {"id": "recent2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_recent(user_id, limit=3)
        
        assert len(result) == 2
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_recent_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска недавних проектов с параметрами по умолчанию"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_recent(user_id)
        
        assert result == []
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_search_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска проектов по запросу"""
        user_id = uuid4()
        query = "test"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "search1"}, {"id": "search2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.search(user_id, query, limit=20, offset=5)
        
        assert len(result) == 2
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_search_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска проектов по запросу с параметрами по умолчанию"""
        user_id = uuid4()
        query = "test"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.search(user_id, query)
        
        assert result == []
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_count_by_user_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного подсчета проектов пользователя"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.count = 15
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.count_by_user(user_id)
        
        assert result == 15
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_count_by_user_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при подсчете проектов пользователя"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Count failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.count_by_user(user_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_name_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при поиске проекта по имени"""
        user_id = uuid4()
        project_name = "Test Project"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Search failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_by_name(user_id, project_name)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_recent_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при поиске недавних проектов"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Recent search failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_recent(user_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_search_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при поиске проектов по запросу"""
        user_id = uuid4()
        query = "test"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Search failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.search(user_id, query)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    async def test_find_by_user_id_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при поиске проектов по ID пользователя"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Find failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_by_user_id(user_id)