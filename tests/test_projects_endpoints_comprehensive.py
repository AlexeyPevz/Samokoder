"""
Комплексные тесты для Projects API endpoints
Покрытие всех эндпоинтов и сценариев ошибок
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException
from datetime import datetime
import uuid
from pathlib import Path

from backend.api.projects import router
from backend.models.requests import ProjectCreateRequest, ProjectUpdateRequest
from backend.models.responses import ProjectResponse, ProjectListResponse, ProjectCreateResponse


class TestProjectsEndpoints:
    """Тесты для всех эндпоинтов проектов"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": str(uuid.uuid4()), "email": "test@example.com"}
    
    @pytest.fixture
    def mock_project_create_request(self):
        return ProjectCreateRequest(
            name="Test Project",
            description="Test project description",
            ai_config={"model": "gpt-4"}
        )
    
    @pytest.fixture
    def mock_project_update_request(self):
        return ProjectUpdateRequest(
            name="Updated Project",
            description="Updated description"
        )
    
    @pytest.fixture
    def mock_supabase_response(self):
        return Mock(
            data=[{
                "id": str(uuid.uuid4()),
                "user_id": str(uuid.uuid4()),
                "name": "Test Project",
                "description": "Test description",
                "status": "draft",
                "ai_config": {"model": "gpt-4"},
                "workspace_path": "workspaces/user123/project456",
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "is_active": True
            }]
        )
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"remaining": 100, "reset_time": 3600}
    
    # === CREATE PROJECT TESTS ===
    
    @pytest.mark.asyncio
    async def test_create_project_success(self, mock_current_user, mock_project_create_request, 
                                        mock_supabase_response, mock_rate_limit):
        """Тест успешного создания проекта"""
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="test-project-id"), \
             patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response), \
             patch('backend.api.projects.transaction'), \
             patch('pathlib.Path.mkdir') as mock_mkdir:
            
            from backend.api.projects import create_project
            
            result = await create_project(mock_project_create_request, mock_current_user, mock_rate_limit)
            
            assert isinstance(result, ProjectCreateResponse)
            assert result.success is True
            assert result.project_id == "test-project-id"
            assert "создан" in result.message
            assert result.status == "draft"
            mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
    
    @pytest.mark.asyncio
    async def test_create_project_invalid_name(self, mock_current_user, mock_project_create_request, 
                                             mock_rate_limit):
        """Тест создания проекта с невалидным именем"""
        with patch('backend.api.projects.validate_project_name', return_value=False):
            
            from backend.api.projects import create_project
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(mock_project_create_request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 400
            assert "Invalid project name" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_project_invalid_description(self, mock_current_user, mock_rate_limit):
        """Тест создания проекта с невалидным описанием"""
        request = ProjectCreateRequest(
            name="Test Project",
            description="<script>alert('xss')</script>",
            ai_config={"model": "gpt-4"}
        )
        
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=False):
            
            from backend.api.projects import create_project
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 400
            assert "Invalid project description" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_project_database_error(self, mock_current_user, mock_project_create_request, 
                                               mock_rate_limit):
        """Тест создания проекта с ошибкой базы данных"""
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="test-project-id"), \
             patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response), \
             patch('backend.api.projects.transaction'):
            
            from backend.api.projects import create_project
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(mock_project_create_request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 500
            assert "Failed to create project" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_project_workspace_error(self, mock_current_user, mock_project_create_request, 
                                                mock_supabase_response, mock_rate_limit):
        """Тест создания проекта с ошибкой создания workspace"""
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="test-project-id"), \
             patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response), \
             patch('backend.api.projects.transaction'), \
             patch('pathlib.Path.mkdir', side_effect=Exception("Permission denied")):
            
            from backend.api.projects import create_project
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(mock_project_create_request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 500
            assert "Failed to create workspace directory" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_project_path_traversal_protection(self, mock_current_user, mock_project_create_request, 
                                                           mock_supabase_response, mock_rate_limit):
        """Тест защиты от path traversal при создании workspace"""
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="../../../etc/passwd"), \
             patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response), \
             patch('backend.api.projects.transaction'):
            
            from backend.api.projects import create_project
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(mock_project_create_request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 400
            assert "Invalid workspace path" in exc_info.value.detail
    
    # === LIST PROJECTS TESTS ===
    
    @pytest.mark.asyncio
    async def test_list_projects_success(self, mock_current_user, mock_supabase_response, mock_rate_limit):
        """Тест успешного получения списка проектов"""
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import list_projects
            
            result = await list_projects(mock_current_user, limit=10, offset=0, project_status=None, search=None, rate_limit=mock_rate_limit)
            
            assert isinstance(result, ProjectListResponse)
            assert result.total_count == 1
            assert len(result.projects) == 1
            assert result.limit == 10
            assert result.page == 1
    
    @pytest.mark.asyncio
    async def test_list_projects_with_filters(self, mock_current_user, mock_supabase_response, mock_rate_limit):
        """Тест получения списка проектов с фильтрами"""
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import list_projects
            
            result = await list_projects(
                mock_current_user, 
                limit=5, 
                offset=10, 
                project_status="draft", 
                search="test", 
                rate_limit=mock_rate_limit
            )
            
            assert isinstance(result, ProjectListResponse)
            assert result.limit == 5
            assert result.page == 3  # offset=10, limit=5 -> page=3
    
    @pytest.mark.asyncio
    async def test_list_projects_empty_result(self, mock_current_user, mock_rate_limit):
        """Тест получения пустого списка проектов"""
        mock_supabase_response = Mock(data=[])
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import list_projects
            
            result = await list_projects(mock_current_user, limit=10, offset=0, project_status=None, search=None, rate_limit=mock_rate_limit)
            
            assert isinstance(result, ProjectListResponse)
            assert result.total_count == 0
            assert len(result.projects) == 0
    
    @pytest.mark.asyncio
    async def test_list_projects_database_error(self, mock_current_user, mock_rate_limit):
        """Тест получения списка проектов с ошибкой базы данных"""
        with patch('backend.api.projects.execute_supabase_operation', side_effect=Exception("DB Error")):
            
            from backend.api.projects import list_projects
            
            with pytest.raises(HTTPException) as exc_info:
                await list_projects(mock_current_user, limit=10, offset=0, project_status=None, search=None, rate_limit=mock_rate_limit)
            
            assert exc_info.value.status_code == 500
            assert "Failed to list projects" in exc_info.value.detail
    
    # === GET PROJECT TESTS ===
    
    @pytest.mark.asyncio
    async def test_get_project_success(self, mock_current_user, mock_supabase_response, mock_rate_limit):
        """Тест успешного получения проекта"""
        project_id = "test-project-id"
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import get_project
            
            result = await get_project(project_id, mock_current_user, mock_rate_limit)
            
            assert isinstance(result, ProjectResponse)
            assert result.id == mock_supabase_response.data[0]["id"]
            assert result.name == mock_supabase_response.data[0]["name"]
    
    @pytest.mark.asyncio
    async def test_get_project_not_found(self, mock_current_user, mock_rate_limit):
        """Тест получения несуществующего проекта"""
        project_id = "non-existent-project"
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import get_project
            
            with pytest.raises(HTTPException) as exc_info:
                await get_project(project_id, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_project_database_error(self, mock_current_user, mock_rate_limit):
        """Тест получения проекта с ошибкой базы данных"""
        project_id = "test-project-id"
        
        with patch('backend.api.projects.execute_supabase_operation', side_effect=Exception("DB Error")):
            
            from backend.api.projects import get_project
            
            with pytest.raises(HTTPException) as exc_info:
                await get_project(project_id, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 500
            assert "Failed to get project" in exc_info.value.detail
    
    # === UPDATE PROJECT TESTS ===
    
    @pytest.mark.asyncio
    async def test_update_project_success(self, mock_current_user, mock_project_update_request, 
                                        mock_supabase_response, mock_rate_limit):
        """Тест успешного обновления проекта"""
        project_id = "test-project-id"
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import update_project
            
            result = await update_project(project_id, mock_project_update_request, mock_current_user, mock_rate_limit)
            
            assert isinstance(result, ProjectResponse)
            assert result.id == mock_supabase_response.data[0]["id"]
    
    @pytest.mark.asyncio
    async def test_update_project_not_found(self, mock_current_user, mock_project_update_request, 
                                          mock_rate_limit):
        """Тест обновления несуществующего проекта"""
        project_id = "non-existent-project"
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import update_project
            
            with pytest.raises(HTTPException) as exc_info:
                await update_project(project_id, mock_project_update_request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_update_project_update_failed(self, mock_current_user, mock_project_update_request, 
                                              mock_rate_limit):
        """Тест неудачного обновления проекта"""
        project_id = "test-project-id"
        
        # Мок для проверки существования проекта
        existing_response = Mock(data=[{"id": project_id}])
        # Мок для неудачного обновления
        update_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation') as mock_execute:
            mock_execute.side_effect = [existing_response, update_response]
            
            from backend.api.projects import update_project
            
            with pytest.raises(HTTPException) as exc_info:
                await update_project(project_id, mock_project_update_request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 500
            assert "Failed to update project" in exc_info.value.detail
    
    # === DELETE PROJECT TESTS ===
    
    @pytest.mark.asyncio
    async def test_delete_project_success(self, mock_current_user, mock_rate_limit):
        """Тест успешного удаления проекта"""
        project_id = "test-project-id"
        
        # Мок для проверки существования проекта
        existing_response = Mock(data=[{"id": project_id}])
        # Мок для успешного удаления
        delete_response = Mock(data=[{"id": project_id, "is_active": False}])
        
        with patch('backend.api.projects.execute_supabase_operation') as mock_execute:
            mock_execute.side_effect = [existing_response, delete_response]
            
            from backend.api.projects import delete_project
            
            result = await delete_project(project_id, mock_current_user, mock_rate_limit)
            
            assert result["message"] == "Проект удален"
    
    @pytest.mark.asyncio
    async def test_delete_project_not_found(self, mock_current_user, mock_rate_limit):
        """Тест удаления несуществующего проекта"""
        project_id = "non-existent-project"
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import delete_project
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_project(project_id, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_delete_project_delete_failed(self, mock_current_user, mock_rate_limit):
        """Тест неудачного удаления проекта"""
        project_id = "test-project-id"
        
        # Мок для проверки существования проекта
        existing_response = Mock(data=[{"id": project_id}])
        # Мок для неудачного удаления
        delete_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation') as mock_execute:
            mock_execute.side_effect = [existing_response, delete_response]
            
            from backend.api.projects import delete_project
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_project(project_id, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 500
            assert "Failed to delete project" in exc_info.value.detail
    
    # === GET PROJECT FILES TESTS ===
    
    @pytest.mark.asyncio
    async def test_get_project_files_success(self, mock_current_user, mock_rate_limit):
        """Тест успешного получения файлов проекта"""
        project_id = "test-project-id"
        
        # Мок для проверки существования проекта
        project_response = Mock(data=[{"id": project_id, "name": "Test Project"}])
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=project_response):
            
            from backend.api.projects import get_project_files
            
            result = await get_project_files(project_id, mock_current_user, mock_rate_limit)
            
            assert "files" in result
            assert "total_count" in result
            assert "project_id" in result
            assert result["project_id"] == project_id
            assert result["total_count"] == 2  # Mock возвращает 2 файла
    
    @pytest.mark.asyncio
    async def test_get_project_files_not_found(self, mock_current_user, mock_rate_limit):
        """Тест получения файлов несуществующего проекта"""
        project_id = "non-existent-project"
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import get_project_files
            
            with pytest.raises(HTTPException) as exc_info:
                await get_project_files(project_id, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail
    
    # === GET FILE CONTENT TESTS ===
    
    @pytest.mark.asyncio
    async def test_get_file_content_success(self, mock_current_user, mock_rate_limit):
        """Тест успешного получения содержимого файла"""
        project_id = "test-project-id"
        file_path = "main.py"
        
        # Мок для проверки существования проекта
        project_response = Mock(data=[{"id": project_id, "name": "Test Project"}])
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=project_response):
            
            from backend.api.projects import get_file_content
            
            result = await get_file_content(project_id, file_path, mock_current_user, mock_rate_limit)
            
            assert "file_path" in result
            assert "content" in result
            assert "project_id" in result
            assert "size" in result
            assert result["file_path"] == file_path
            assert result["project_id"] == project_id
            assert file_path in result["content"]  # Mock content содержит путь к файлу
    
    @pytest.mark.asyncio
    async def test_get_file_content_project_not_found(self, mock_current_user, mock_rate_limit):
        """Тест получения содержимого файла несуществующего проекта"""
        project_id = "non-existent-project"
        file_path = "main.py"
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import get_file_content
            
            with pytest.raises(HTTPException) as exc_info:
                await get_file_content(project_id, file_path, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail
    
    # === CHAT WITH PROJECT TESTS ===
    
    @pytest.mark.asyncio
    async def test_chat_with_project_success(self, mock_current_user, mock_rate_limit):
        """Тест успешного чата с проектом"""
        project_id = "test-project-id"
        chat_data = {"message": "Hello, AI!"}
        
        # Мок для проверки существования проекта
        project_response = Mock(data=[{"id": project_id, "name": "Test Project"}])
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=project_response):
            
            from backend.api.projects import chat_with_project
            
            result = await chat_with_project(project_id, chat_data, mock_current_user, mock_rate_limit)
            
            assert "message" in result
            assert "project_id" in result
            assert "timestamp" in result
            assert "agent" in result
            assert result["project_id"] == project_id
            assert "AI Assistant" in result["message"]
            assert chat_data["message"] in result["message"]
    
    @pytest.mark.asyncio
    async def test_chat_with_project_not_found(self, mock_current_user, mock_rate_limit):
        """Тест чата с несуществующим проектом"""
        project_id = "non-existent-project"
        chat_data = {"message": "Hello, AI!"}
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import chat_with_project
            
            with pytest.raises(HTTPException) as exc_info:
                await chat_with_project(project_id, chat_data, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail
    
    # === GENERATE PROJECT CODE TESTS ===
    
    @pytest.mark.asyncio
    async def test_generate_project_code_success(self, mock_current_user, mock_rate_limit):
        """Тест успешной генерации кода для проекта"""
        project_id = "test-project-id"
        generation_data = {"prompt": "Create a simple Python function"}
        
        # Мок для проверки существования проекта
        project_response = Mock(data=[{"id": project_id, "name": "Test Project"}])
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=project_response):
            
            from backend.api.projects import generate_project_code
            
            result = await generate_project_code(project_id, generation_data, mock_current_user, mock_rate_limit)
            
            assert "generated_files" in result
            assert "message" in result
            assert "project_id" in result
            assert "timestamp" in result
            assert result["project_id"] == project_id
            assert len(result["generated_files"]) == 1
            assert generation_data["prompt"] in result["generated_files"][0]["content"]
    
    @pytest.mark.asyncio
    async def test_generate_project_code_not_found(self, mock_current_user, mock_rate_limit):
        """Тест генерации кода для несуществующего проекта"""
        project_id = "non-existent-project"
        generation_data = {"prompt": "Create a simple Python function"}
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import generate_project_code
            
            with pytest.raises(HTTPException) as exc_info:
                await generate_project_code(project_id, generation_data, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail
    
    # === EXPORT PROJECT TESTS ===
    
    @pytest.mark.asyncio
    async def test_export_project_success(self, mock_current_user, mock_rate_limit):
        """Тест успешного экспорта проекта"""
        project_id = "test-project-id"
        
        # Мок для проверки существования проекта
        project_response = Mock(data=[{"id": project_id, "name": "Test Project"}])
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=project_response):
            
            from backend.api.projects import export_project
            
            result = await export_project(project_id, mock_current_user, mock_rate_limit)
            
            assert "message" in result
            assert "project_id" in result
            assert "download_url" in result
            assert "status" in result
            assert result["project_id"] == project_id
            assert "export" in result["download_url"]
    
    @pytest.mark.asyncio
    async def test_export_project_not_found(self, mock_current_user, mock_rate_limit):
        """Тест экспорта несуществующего проекта"""
        project_id = "non-existent-project"
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.projects import export_project
            
            with pytest.raises(HTTPException) as exc_info:
                await export_project(project_id, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == 404
            assert "Project not found" in exc_info.value.detail