"""
Комплексные тесты для ProjectRepository (14% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime, timezone

from backend.repositories.project_repository import ProjectRepository
from backend.core.exceptions import DatabaseError, NotFoundError, ValidationError, ConnectionError, TimeoutError, ProjectError


class TestProjectRepository:
    """Тесты для ProjectRepository"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.repository = ProjectRepository()
        self.mock_supabase = AsyncMock()
        self.mock_response = Mock()
        self.mock_response.data = [{"id": "123", "name": "Test Project"}]

    @patch('backend.repositories.project_repository.connection_pool_manager')
    def test_init(self, mock_pool_manager):
        """Тест инициализации ProjectRepository"""
        repository = ProjectRepository()
        assert repository._supabase is None
        assert hasattr(repository, '_get_supabase')

    @patch('backend.repositories.project_repository.connection_pool_manager')
    def test_get_supabase_initial(self, mock_pool_manager):
        """Тест получения Supabase клиента при первом вызове"""
        mock_client = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_client
        
        repository = ProjectRepository()
        result = repository._get_supabase()
        
        assert result == mock_client
        assert repository._supabase == mock_client
        mock_pool_manager.get_supabase_client.assert_called_once()

    @patch('backend.repositories.project_repository.connection_pool_manager')
    def test_get_supabase_cached(self, mock_pool_manager):
        """Тест получения кэшированного Supabase клиента"""
        mock_client = Mock()
        repository = ProjectRepository()
        repository._supabase = mock_client
        
        result = repository._get_supabase()
        
        assert result == mock_client
        mock_pool_manager.get_supabase_client.assert_not_called()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_id_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска проекта по ID"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.return_value = self.mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.find_by_id(project_id)
        
        # Assert
        assert result == self.mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_id_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска несуществующего проекта"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.find_by_id(project_id)
        
        # Assert
        assert result is None

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_id_connection_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ConnectionError при поиске проекта"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ConnectionError("Connection failed")
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_by_id(project_id)
        assert "Database connection failed" in str(exc_info.value)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_id_timeout_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки TimeoutError при поиске проекта"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = TimeoutError("Timeout")
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_by_id(project_id)
        assert "Database operation timed out" in str(exc_info.value)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_id_general_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки общего исключения при поиске проекта"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("General error")
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_by_id(project_id)
        assert "Database operation failed" in str(exc_info.value)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_user_id_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска проектов по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [
            {"id": "123", "name": "Project 1"},
            {"id": "124", "name": "Project 2"}
        ]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act
        result = await self.repository.find_by_user_id(user_id, limit=10, offset=0)
        
        # Assert
        assert len(result) == 2
        assert result[0]["name"] == "Project 1"
        assert result[1]["name"] == "Project 2"
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_user_id_empty(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска проектов по пользователю - пустой результат"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act
        result = await self.repository.find_by_user_id(user_id)
        
        # Assert
        assert result == []

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_user_id_with_pagination(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска проектов по пользователю с пагинацией"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "123", "name": "Project 1"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act
        result = await self.repository.find_by_user_id(user_id, limit=5, offset=10)
        
        # Assert
        assert len(result) == 1
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_user_id_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при поиске проектов по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("Database error")
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError):
            await self.repository.find_by_user_id(user_id)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_create_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного создания проекта"""
        # Arrange
        project_data = {
            "id": str(uuid4()),
            "user_id": str(uuid4()),
            "name": "New Project",
            "description": "Project description"
        }
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [project_data]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        
        # Act
        result = await self.repository.create(project_data)
        
        # Assert
        assert result == project_data
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_create_validation_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ValidationError при создании проекта"""
        # Arrange
        project_data = {"name": "New Project"}  # Неполные данные
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ValidationError("Validation failed")
        mock_db_config.TABLES = {"projects": "projects"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.create(project_data)
        assert "Database operation failed" in str(exc_info.value)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_update_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного обновления проекта"""
        # Arrange
        project_id = uuid4()
        update_data = {"name": "Updated Project"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(project_id), "name": "Updated Project"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.update(project_id, update_data)
        
        # Assert
        assert result == mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_update_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обновления несуществующего проекта"""
        # Arrange
        project_id = uuid4()
        update_data = {"name": "Updated Project"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.update(project_id, update_data)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_delete_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного удаления проекта"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(project_id)}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.delete(project_id)
        
        # Assert
        assert result is True
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_delete_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест удаления несуществующего проекта"""
        # Arrange
        project_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.delete(project_id)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_count_by_user_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного подсчета проектов по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.count = 5
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act
        result = await self.repository.count_by_user(user_id)
        
        # Assert
        assert result == 5
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_count_by_user_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при подсчете проектов по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("Database error")
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.COLUMNS = {"user_id": "user_id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError):
            await self.repository.count_by_user(user_id)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_name_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска проекта по имени"""
        # Arrange
        user_id = uuid4()
        project_name = "Test Project"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "123", "name": "Test Project"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id", "name": "name"}
        
        # Act
        result = await self.repository.find_by_name(user_id, project_name)
        
        # Assert
        assert result == mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_name_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска несуществующего проекта по имени"""
        # Arrange
        user_id = uuid4()
        project_name = "Non-existent Project"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id", "name": "name"}
        
        # Act
        result = await self.repository.find_by_name(user_id, project_name)
        
        # Assert
        assert result is None

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_by_name_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при поиске проекта по имени"""
        # Arrange
        user_id = uuid4()
        project_name = "Test Project"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ConnectionError("Connection failed")
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id", "name": "name"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_by_name(user_id, project_name)
        assert "Database connection failed" in str(exc_info.value)

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_active_by_user_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска активных проектов по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "123", "name": "Active Project", "is_active": True}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id", "is_active": "is_active"}
        
        # Act
        result = await self.repository.find_active_by_user(user_id)
        
        # Assert
        assert len(result) == 1
        assert result[0]["is_active"] is True
        mock_execute.assert_called_once()

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_active_by_user_empty(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска активных проектов по пользователю - пустой результат"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id", "is_active": "is_active"}
        
        # Act
        result = await self.repository.find_active_by_user(user_id)
        
        # Assert
        assert result == []

    @patch('backend.repositories.project_repository.execute_supabase_operation')
    @patch('backend.repositories.project_repository.connection_pool_manager')
    @patch('backend.repositories.project_repository.db_config')
    async def test_find_active_by_user_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при поиске активных проектов по пользователю"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = TimeoutError("Timeout")
        mock_db_config.TABLES = {"projects": "projects"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"user_id": "user_id", "is_active": "is_active"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_active_by_user(user_id)
        assert "Database operation timed out" in str(exc_info.value)