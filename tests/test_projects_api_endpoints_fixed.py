"""
Comprehensive tests for Projects API endpoints - Fixed version
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, status
from backend.api.projects import router
from backend.models.requests import ProjectCreateRequest, ProjectUpdateRequest
from backend.models.responses import ProjectResponse, ProjectListResponse, ProjectCreateResponse, ProjectStatus
from backend.auth.dependencies import get_current_user
from backend.middleware.secure_rate_limiter import api_rate_limit
import uuid
from datetime import datetime


class TestProjectsAPICreate:
    """Test project creation endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        """Mock current user"""
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        """Mock rate limit"""
        return {"requests": 1, "limit": 100}
    
    @pytest.fixture
    def valid_project_data(self):
        """Valid project creation data"""
        return {
            "name": "Test Project",
            "description": "A test project description",
            "ai_config": {"model": "gpt-4"}
        }
    
    @pytest.mark.asyncio
    async def test_create_project_success(self, mock_current_user, mock_rate_limit, valid_project_data):
        """Test successful project creation"""
        from backend.api.projects import create_project
        
        # Mock dependencies
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="project123"), \
             patch('backend.api.projects.transaction'), \
             patch('backend.api.projects.execute_supabase_operation') as mock_supabase, \
             patch('backend.api.projects.Path') as mock_path:
            
            # Mock Supabase response
            mock_supabase.return_value = Mock(data=[{"id": "project123"}])
            
            # Mock path operations
            mock_path_obj = Mock()
            mock_path.return_value = mock_path_obj
            mock_path_obj.resolve.return_value = mock_path_obj
            mock_path_obj.mkdir.return_value = None
            
            # Mock base workspace path
            base_workspace = Mock()
            base_workspace.resolve.return_value = base_workspace
            mock_path.side_effect = lambda x: base_workspace if x == "workspaces" else mock_path_obj
            
            # Mock str conversion for path comparison
            mock_path_obj.__str__ = Mock(return_value="/workspace/workspaces/user123/project123")
            base_workspace.__str__ = Mock(return_value="/workspace/workspaces")
            
            request = ProjectCreateRequest(**valid_project_data)
            result = await create_project(request, mock_current_user, mock_rate_limit)
            
            assert isinstance(result, ProjectCreateResponse)
            assert result.project_id == "project123"
            assert result.message == "Проект создан, готов к работе"
            assert result.status == ProjectStatus.DRAFT
            assert result.workspace == "workspaces/user123/project123"
    
    @pytest.mark.asyncio
    async def test_create_project_invalid_name(self, mock_current_user, mock_rate_limit, valid_project_data):
        """Test project creation with invalid name"""
        from backend.api.projects import create_project
        
        with patch('backend.api.projects.validate_project_name', return_value=False):
            request = ProjectCreateRequest(**valid_project_data)
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid project name" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_create_project_invalid_description(self, mock_current_user, mock_rate_limit, valid_project_data):
        """Test project creation with invalid description"""
        from backend.api.projects import create_project
        
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=False):
            
            request = ProjectCreateRequest(**valid_project_data)
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid project description" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_create_project_database_error(self, mock_current_user, mock_rate_limit, valid_project_data):
        """Test project creation with database error"""
        from backend.api.projects import create_project
        
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="project123"), \
             patch('backend.api.projects.transaction'), \
             patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=None)):
            
            request = ProjectCreateRequest(**valid_project_data)
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Failed to create project" in str(exc_info.value.detail)


class TestProjectsAPIList:
    """Test project listing endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_list_projects_success(self, mock_current_user, mock_rate_limit):
        """Test successful project listing"""
        from backend.api.projects import list_projects
        
        mock_projects_data = [
            {
                "id": "project1",
                "user_id": "user123",
                "name": "Project 1",
                "description": "Description 1",
                "status": "draft",
                "ai_config": {"model": "gpt-4"},
                "workspace_path": "workspaces/user123/project1",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ]
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=mock_projects_data)):
            result = await list_projects(mock_current_user, limit=10, offset=0, status=None, search=None, rate_limit=mock_rate_limit)
            
            assert isinstance(result, ProjectListResponse)
            assert len(result.projects) == 1
            assert result.total_count == 1
            assert result.page == 0
            assert result.limit == 10
            assert result.projects[0].id == "project1"
    
    @pytest.mark.asyncio
    async def test_list_projects_empty_result(self, mock_current_user, mock_rate_limit):
        """Test project listing with empty results"""
        from backend.api.projects import list_projects
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            result = await list_projects(mock_current_user, limit=10, offset=0, status=None, search=None, rate_limit=mock_rate_limit)
            
            assert isinstance(result, ProjectListResponse)
            assert len(result.projects) == 0
            assert result.total_count == 0


class TestProjectsAPIGet:
    """Test get project endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_get_project_success(self, mock_current_user, mock_rate_limit):
        """Test successful project retrieval"""
        from backend.api.projects import get_project
        
        mock_project_data = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project",
            "description": "Test Description",
            "status": "draft",
            "ai_config": {"model": "gpt-4"},
            "workspace_path": "workspaces/user123/project123",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[mock_project_data])):
            result = await get_project("project123", mock_current_user, mock_rate_limit)
            
            assert isinstance(result, ProjectResponse)
            assert result.id == "project123"
            assert result.user_id == "user123"
            assert result.name == "Test Project"
            assert result.status == ProjectStatus.DRAFT
    
    @pytest.mark.asyncio
    async def test_get_project_not_found(self, mock_current_user, mock_rate_limit):
        """Test get project when project not found"""
        from backend.api.projects import get_project
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            with pytest.raises(HTTPException) as exc_info:
                await get_project("nonexistent", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)


class TestProjectsAPIUpdate:
    """Test update project endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.fixture
    def update_data(self):
        return {
            "name": "Updated Project",
            "description": "Updated Description",
            "ai_config": {"model": "claude-3"}
        }
    
    @pytest.mark.asyncio
    async def test_update_project_success(self, mock_current_user, mock_rate_limit, update_data):
        """Test successful project update"""
        from backend.api.projects import update_project
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Original Project",
            "description": "Original Description",
            "status": "draft",
            "ai_config": {"model": "gpt-4"},
            "workspace_path": "workspaces/user123/project123",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        
        updated_project = {
            **existing_project,
            **update_data,
            "updated_at": "2024-01-02T00:00:00Z"
        }
        
        with patch('backend.api.projects.execute_supabase_operation') as mock_supabase:
            # Mock existing project check
            mock_supabase.return_value = Mock(data=[existing_project])
            # Mock update response
            mock_supabase.side_effect = [
                Mock(data=[existing_project]),  # First call for check
                Mock(data=[updated_project])    # Second call for update
            ]
            
            request = ProjectUpdateRequest(**update_data)
            result = await update_project("project123", request, mock_current_user, mock_rate_limit)
            
            assert isinstance(result, ProjectResponse)
            assert result.id == "project123"
            assert result.user_id == "user123"
            assert result.name == "Updated Project"
            assert result.description == "Updated Description"
            assert result.ai_config == {"model": "claude-3"}
    
    @pytest.mark.asyncio
    async def test_update_project_not_found(self, mock_current_user, mock_rate_limit, update_data):
        """Test update project when project not found"""
        from backend.api.projects import update_project
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            request = ProjectUpdateRequest(**update_data)
            
            with pytest.raises(HTTPException) as exc_info:
                await update_project("nonexistent", request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)


class TestProjectsAPIDelete:
    """Test delete project endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_delete_project_success(self, mock_current_user, mock_rate_limit):
        """Test successful project deletion"""
        from backend.api.projects import delete_project
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project",
            "is_active": True
        }
        
        with patch('backend.api.projects.execute_supabase_operation') as mock_supabase:
            # Mock existing project check
            mock_supabase.return_value = Mock(data=[existing_project])
            # Mock successful deletion
            mock_supabase.side_effect = [
                Mock(data=[existing_project]),  # First call for check
                Mock(data=[{"id": "project123", "is_active": False}])  # Second call for deletion
            ]
            
            result = await delete_project("project123", mock_current_user, mock_rate_limit)
            
            assert result == {"message": "Проект удален"}
    
    @pytest.mark.asyncio
    async def test_delete_project_not_found(self, mock_current_user, mock_rate_limit):
        """Test delete project when project not found"""
        from backend.api.projects import delete_project
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            with pytest.raises(HTTPException) as exc_info:
                await delete_project("nonexistent", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)


class TestProjectsAPIFiles:
    """Test project files endpoints"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_get_project_files_success(self, mock_current_user, mock_rate_limit):
        """Test successful project files listing"""
        from backend.api.projects import get_project_files
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project"
        }
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[existing_project])):
            result = await get_project_files("project123", mock_current_user, mock_rate_limit)
            
            assert "files" in result
            assert "total_count" in result
            assert "project_id" in result
            assert result["project_id"] == "project123"
            assert result["total_count"] == 2
            assert len(result["files"]) == 2
            assert result["files"][0]["name"] == "main.py"
            assert result["files"][1]["name"] == "requirements.txt"
    
    @pytest.mark.asyncio
    async def test_get_project_files_not_found(self, mock_current_user, mock_rate_limit):
        """Test get project files when project not found"""
        from backend.api.projects import get_project_files
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            with pytest.raises(HTTPException) as exc_info:
                await get_project_files("nonexistent", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_file_content_success(self, mock_current_user, mock_rate_limit):
        """Test successful file content retrieval"""
        from backend.api.projects import get_file_content
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project"
        }
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[existing_project])):
            result = await get_file_content("project123", "main.py", mock_current_user, mock_rate_limit)
            
            assert "file_path" in result
            assert "content" in result
            assert "project_id" in result
            assert "size" in result
            assert result["file_path"] == "main.py"
            assert result["project_id"] == "project123"
            assert "Mock content for main.py" in result["content"]
    
    @pytest.mark.asyncio
    async def test_get_file_content_not_found(self, mock_current_user, mock_rate_limit):
        """Test get file content when project not found"""
        from backend.api.projects import get_file_content
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            with pytest.raises(HTTPException) as exc_info:
                await get_file_content("nonexistent", "main.py", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)


class TestProjectsAPIChat:
    """Test project chat endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_chat_with_project_success(self, mock_current_user, mock_rate_limit):
        """Test successful chat with project"""
        from backend.api.projects import chat_with_project
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project"
        }
        
        chat_data = {"message": "Hello, AI!"}
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[existing_project])):
            result = await chat_with_project("project123", chat_data, mock_current_user, mock_rate_limit)
            
            assert "message" in result
            assert "project_id" in result
            assert "timestamp" in result
            assert "agent" in result
            assert result["project_id"] == "project123"
            assert "Hello, AI!" in result["message"]
            assert result["agent"] == "project_ai"
    
    @pytest.mark.asyncio
    async def test_chat_with_project_not_found(self, mock_current_user, mock_rate_limit):
        """Test chat with project when project not found"""
        from backend.api.projects import chat_with_project
        
        chat_data = {"message": "Hello, AI!"}
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            with pytest.raises(HTTPException) as exc_info:
                await chat_with_project("nonexistent", chat_data, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)


class TestProjectsAPIGenerate:
    """Test project code generation endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_generate_project_code_success(self, mock_current_user, mock_rate_limit):
        """Test successful code generation"""
        from backend.api.projects import generate_project_code
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project"
        }
        
        generation_data = {"prompt": "Create a hello world function"}
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[existing_project])):
            result = await generate_project_code("project123", generation_data, mock_current_user, mock_rate_limit)
            
            assert "generated_files" in result
            assert "message" in result
            assert "project_id" in result
            assert "timestamp" in result
            assert result["project_id"] == "project123"
            assert result["message"] == "Code generation completed"
            assert len(result["generated_files"]) == 1
            assert result["generated_files"][0]["path"] == "generated_file.py"
    
    @pytest.mark.asyncio
    async def test_generate_project_code_not_found(self, mock_current_user, mock_rate_limit):
        """Test code generation when project not found"""
        from backend.api.projects import generate_project_code
        
        generation_data = {"prompt": "Create a hello world function"}
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            with pytest.raises(HTTPException) as exc_info:
                await generate_project_code("nonexistent", generation_data, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)


class TestProjectsAPIExport:
    """Test project export endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_export_project_success(self, mock_current_user, mock_rate_limit):
        """Test successful project export"""
        from backend.api.projects import export_project
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project"
        }
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[existing_project])):
            result = await export_project("project123", mock_current_user, mock_rate_limit)
            
            assert "message" in result
            assert "project_id" in result
            assert "download_url" in result
            assert "status" in result
            assert result["project_id"] == "project123"
            assert result["message"] == "Project export initiated"
            assert result["status"] == "processing"
            assert f"/api/projects/{result['project_id']}/download/export.zip" == result["download_url"]
    
    @pytest.mark.asyncio
    async def test_export_project_not_found(self, mock_current_user, mock_rate_limit):
        """Test project export when project not found"""
        from backend.api.projects import export_project
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[])):
            with pytest.raises(HTTPException) as exc_info:
                await export_project("nonexistent", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "Project not found" in str(exc_info.value.detail)


class TestProjectsAPIEdgeCases:
    """Test edge cases and error scenarios"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.mark.asyncio
    async def test_create_project_empty_ai_config(self, mock_current_user, mock_rate_limit):
        """Test project creation with empty AI config"""
        from backend.api.projects import create_project
        
        project_data = {
            "name": "Test Project",
            "description": "Test Description",
            "ai_config": None
        }
        
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="project123"), \
             patch('backend.api.projects.transaction'), \
             patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[{"id": "project123"}])), \
             patch('backend.api.projects.Path') as mock_path:
            
            mock_path_obj = Mock()
            mock_path.return_value = mock_path_obj
            mock_path_obj.resolve.return_value = mock_path_obj
            mock_path_obj.mkdir.return_value = None
            
            base_workspace = Mock()
            base_workspace.resolve.return_value = base_workspace
            mock_path.side_effect = lambda x: base_workspace if x == "workspaces" else mock_path_obj
            
            mock_path_obj.__str__ = Mock(return_value="/workspace/workspaces/user123/project123")
            base_workspace.__str__ = Mock(return_value="/workspace/workspaces")
            
            request = ProjectCreateRequest(**project_data)
            result = await create_project(request, mock_current_user, mock_rate_limit)
            
            assert isinstance(result, ProjectCreateResponse)
            assert result.project_id == "project123"
    
    @pytest.mark.asyncio
    async def test_update_project_partial_data(self, mock_current_user, mock_rate_limit):
        """Test project update with partial data"""
        from backend.api.projects import update_project
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Original Project",
            "description": "Original Description",
            "status": "draft",
            "ai_config": {"model": "gpt-4"},
            "workspace_path": "workspaces/user123/project123",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        
        # Only update name
        update_data = {"name": "Updated Name"}
        
        with patch('backend.api.projects.execute_supabase_operation') as mock_supabase:
            mock_supabase.return_value = Mock(data=[existing_project])
            mock_supabase.side_effect = [
                Mock(data=[existing_project]),  # First call for check
                Mock(data=[{**existing_project, "name": "Updated Name"}])  # Second call for update
            ]
            
            request = ProjectUpdateRequest(**update_data)
            result = await update_project("project123", request, mock_current_user, mock_rate_limit)
            
            assert result.name == "Updated Name"
    
    @pytest.mark.asyncio
    async def test_chat_with_empty_message(self, mock_current_user, mock_rate_limit):
        """Test chat with empty message"""
        from backend.api.projects import chat_with_project
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project"
        }
        
        chat_data = {"message": ""}
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[existing_project])):
            result = await chat_with_project("project123", chat_data, mock_current_user, mock_rate_limit)
            
            assert "I received your message: ''" in result["message"]
    
    @pytest.mark.asyncio
    async def test_generate_with_empty_prompt(self, mock_current_user, mock_rate_limit):
        """Test code generation with empty prompt"""
        from backend.api.projects import generate_project_code
        
        existing_project = {
            "id": "project123",
            "user_id": "user123",
            "name": "Test Project"
        }
        
        generation_data = {"prompt": ""}
        
        with patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[existing_project])):
            result = await generate_project_code("project123", generation_data, mock_current_user, mock_rate_limit)
            
            assert "Generated code for:" in result["generated_files"][0]["content"]
    
    @pytest.mark.asyncio
    async def test_path_traversal_protection(self, mock_current_user, mock_rate_limit):
        """Test path traversal protection in project creation"""
        from backend.api.projects import create_project
        
        project_data = {
            "name": "Test Project",
            "description": "Test Description"
        }
        
        with patch('backend.api.projects.validate_project_name', return_value=True), \
             patch('backend.api.projects.validate_xss_input', return_value=True), \
             patch('backend.api.projects.generate_unique_uuid', return_value="project123"), \
             patch('backend.api.projects.transaction'), \
             patch('backend.api.projects.execute_supabase_operation', return_value=Mock(data=[{"id": "project123"}])), \
             patch('backend.api.projects.Path') as mock_path:
            
            mock_path_obj = Mock()
            mock_path.return_value = mock_path_obj
            mock_path_obj.resolve.return_value = mock_path_obj
            
            base_workspace = Mock()
            base_workspace.resolve.return_value = base_workspace
            mock_path.side_effect = lambda x: base_workspace if x == "workspaces" else mock_path_obj
            
            # Simulate path traversal attempt
            mock_path_obj.__str__ = Mock(return_value="/etc/passwd")
            base_workspace.__str__ = Mock(return_value="/workspace/workspaces")
            
            request = ProjectCreateRequest(**project_data)
            
            with pytest.raises(HTTPException) as exc_info:
                await create_project(request, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid workspace path" in str(exc_info.value.detail)