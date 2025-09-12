"""
Basic tests for Projects API models
"""
import pytest
from backend.models.requests import ProjectCreateRequest, ProjectUpdateRequest
from backend.models.responses import ProjectResponse, ProjectListResponse, ProjectCreateResponse
from datetime import datetime


class TestProjectCreateRequest:
    """Test ProjectCreateRequest model"""
    
    def test_valid_project_create_request(self):
        """Test valid project creation request"""
        request = ProjectCreateRequest(
            name="Test Project",
            description="Test Description",
            ai_config={"provider": "openai"}
        )
        
        assert request.name == "Test Project"
        assert request.description == "Test Description"
        assert request.ai_config == {"provider": "openai"}
    
    def test_minimal_project_create_request(self):
        """Test minimal project creation request"""
        request = ProjectCreateRequest(
            name="Minimal Project",
            description="Minimal project description for testing"
        )
        
        assert request.name == "Minimal Project"
        assert request.description == "Minimal project description for testing"
        assert request.ai_config is None
    
    def test_project_create_request_with_long_name(self):
        """Test project creation with long name"""
        long_name = "A" * 100
        request = ProjectCreateRequest(
            name=long_name,
            description="Long name project description for testing"
        )
        
        assert request.name == long_name
    
    def test_project_create_request_with_special_characters(self):
        """Test project creation with special characters"""
        request = ProjectCreateRequest(
            name="Project-With_Special.Chars",
            description="Description with émojis 🚀 and special chars"
        )
        
        assert request.name == "Project-With_Special.Chars"
        assert request.description == "Description with émojis 🚀 and special chars"


class TestProjectUpdateRequest:
    """Test ProjectUpdateRequest model"""
    
    def test_valid_project_update_request(self):
        """Test valid project update request"""
        request = ProjectUpdateRequest(
            name="Updated Project",
            description="Updated Description",
            ai_config={"provider": "anthropic"}
        )
        
        assert request.name == "Updated Project"
        assert request.description == "Updated Description"
        assert request.ai_config == {"provider": "anthropic"}
    
    def test_partial_project_update_request(self):
        """Test partial project update request"""
        request = ProjectUpdateRequest(name="Updated Name Only")
        
        assert request.name == "Updated Name Only"
        assert request.description is None
        assert request.ai_config is None
    
    def test_empty_project_update_request(self):
        """Test empty project update request"""
        request = ProjectUpdateRequest()
        
        assert request.name is None
        assert request.description is None
        assert request.ai_config is None


class TestProjectResponse:
    """Test ProjectResponse model"""
    
    def test_valid_project_response(self):
        """Test valid project response"""
        from datetime import datetime
        from backend.models.requests import ProjectStatus
        
        response = ProjectResponse(
            id="test-project-id",
            user_id="user-123",
            name="Test Project",
            description="Test Description",
            status=ProjectStatus.DRAFT,
            ai_config={"provider": "openai"},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        assert response.id == "test-project-id"
        assert response.user_id == "user-123"
        assert response.name == "Test Project"
        assert response.description == "Test Description"
        assert response.status == ProjectStatus.DRAFT
        assert response.ai_config == {"provider": "openai"}
    
    def test_project_response_with_minimal_data(self):
        """Test project response with minimal data"""
        from datetime import datetime
        from backend.models.requests import ProjectStatus
        
        response = ProjectResponse(
            id="minimal-project-id",
            user_id="user-456",
            name="Minimal Project",
            description="Minimal description",
            status=ProjectStatus.DRAFT,
            ai_config={},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        assert response.id == "minimal-project-id"
        assert response.user_id == "user-456"
        assert response.name == "Minimal Project"
        assert response.description == "Minimal description"
        assert response.ai_config == {}


class TestProjectListResponse:
    """Test ProjectListResponse model"""
    
    def test_valid_project_list_response(self):
        """Test valid project list response"""
        from datetime import datetime
        from backend.models.requests import ProjectStatus
        
        projects = [
            ProjectResponse(
                id="project-1",
                user_id="user-123",
                name="Project 1",
                description="Description 1",
                status=ProjectStatus.DRAFT,
                ai_config={"provider": "openai"},
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            ProjectResponse(
                id="project-2",
                user_id="user-123",
                name="Project 2",
                description="Description 2",
                status=ProjectStatus.DRAFT,
                ai_config={"provider": "anthropic"},
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        ]
        
        response = ProjectListResponse(
            projects=projects,
            total_count=2,
            page=1,
            limit=10
        )
        
        assert len(response.projects) == 2
        assert response.total_count == 2
        assert response.page == 1
        assert response.limit == 10
        assert response.projects[0].name == "Project 1"
        assert response.projects[1].name == "Project 2"
    
    def test_empty_project_list_response(self):
        """Test empty project list response"""
        response = ProjectListResponse(
            projects=[],
            total_count=0,
            page=1,
            limit=10
        )
        
        assert len(response.projects) == 0
        assert response.total_count == 0
        assert response.page == 1
        assert response.limit == 10
    
    def test_project_list_response_with_pagination(self):
        """Test project list response with pagination"""
        from datetime import datetime
        from backend.models.requests import ProjectStatus
        
        projects = [
            ProjectResponse(
                id="project-1",
                user_id="user-123",
                name="Project 1",
                description="Description 1",
                status=ProjectStatus.DRAFT,
                ai_config={"provider": "openai"},
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        ]
        
        response = ProjectListResponse(
            projects=projects,
            total_count=50,
            page=3,
            limit=10
        )
        
        assert len(response.projects) == 1
        assert response.total_count == 50
        assert response.page == 3
        assert response.limit == 10


class TestProjectCreateResponse:
    """Test ProjectCreateResponse model"""
    
    def test_valid_project_create_response(self):
        """Test valid project creation response"""
        from backend.models.requests import ProjectStatus
        
        response = ProjectCreateResponse(
            project_id="new-project-id",
            message="Проект создан, готов к работе",
            status=ProjectStatus.DRAFT,
            workspace="/workspace/new-project-id"
        )
        
        assert response.project_id == "new-project-id"
        assert response.message == "Проект создан, готов к работе"
        assert response.status == ProjectStatus.DRAFT
        assert response.workspace == "/workspace/new-project-id"
    
    def test_project_create_response_with_custom_message(self):
        """Test project creation response with custom message"""
        from backend.models.requests import ProjectStatus
        
        response = ProjectCreateResponse(
            project_id="custom-project-id",
            message="Custom creation message",
            status=ProjectStatus.DRAFT,
            workspace="/workspace/custom-project-id"
        )
        
        assert response.project_id == "custom-project-id"
        assert response.message == "Custom creation message"
        assert response.status == ProjectStatus.DRAFT


class TestProjectsWorkflow:
    """Test complete projects workflow"""
    
    def test_create_to_list_workflow(self):
        """Test create project then list workflow"""
        from datetime import datetime
        from backend.models.requests import ProjectStatus
        
        # Create project request
        create_request = ProjectCreateRequest(
            name="Workflow Project",
            description="Test workflow description",
            ai_config={"provider": "openai"}
        )
        
        assert create_request.name == "Workflow Project"
        
        # Create response
        create_response = ProjectCreateResponse(
            project_id="workflow-project-id",
            message="Проект создан, готов к работе",
            status=ProjectStatus.DRAFT,
            workspace="/workspace/workflow-project-id"
        )
        
        assert create_response.project_id == "workflow-project-id"
        
        # Project response for list
        project_response = ProjectResponse(
            id="workflow-project-id",
            user_id="user-123",
            name="Workflow Project",
            description="Test workflow description",
            status=ProjectStatus.DRAFT,
            ai_config={"provider": "openai"},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # List response
        list_response = ProjectListResponse(
            projects=[project_response],
            total_count=1,
            page=1,
            limit=10
        )
        
        assert len(list_response.projects) == 1
        assert list_response.projects[0].name == "Workflow Project"
    
    def test_update_workflow(self):
        """Test update project workflow"""
        from datetime import datetime
        from backend.models.requests import ProjectStatus
        
        # Original project
        original_project = ProjectResponse(
            id="update-project-id",
            user_id="user-123",
            name="Original Name",
            description="Original Description",
            status=ProjectStatus.DRAFT,
            ai_config={"provider": "openai"},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # Update request
        update_request = ProjectUpdateRequest(
            name="Updated Name",
            description="Updated Description"
        )
        
        # Updated project
        updated_project = ProjectResponse(
            id="update-project-id",
            user_id="user-123",
            name="Updated Name",
            description="Updated Description",
            status=ProjectStatus.DRAFT,
            ai_config={"provider": "openai"},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        assert original_project.name == "Original Name"
        assert updated_project.name == "Updated Name"
        assert original_project.id == updated_project.id


class TestProjectValidation:
    """Test project model validation"""
    
    def test_project_name_validation(self):
        """Test project name validation"""
        # Valid names
        valid_names = [
            "Simple Project",
            "Project-With-Dashes",
            "Project_With_Underscores",
            "Project123",
            "Проект с русскими символами"
        ]
        
        for name in valid_names:
            request = ProjectCreateRequest(
                name=name,
                description="Valid project description"
            )
            assert request.name == name
    
    def test_project_ai_config_validation(self):
        """Test project AI config validation"""
        # Valid AI configs
        valid_configs = [
            {"provider": "openai"},
            {"provider": "anthropic", "model": "claude-3"},
            {"provider": "custom", "endpoint": "http://localhost:8000"},
            {}
        ]
        
        for config in valid_configs:
            request = ProjectCreateRequest(
                name="Test Project",
                description="Test project description",
                ai_config=config
            )
            assert request.ai_config == config
    
    def test_project_description_validation(self):
        """Test project description validation"""
        # Valid descriptions
        valid_descriptions = [
            "Simple description",
            "Description with numbers 123",
            "Description with special chars: @#$%",
            "Описание на русском языке",
            None
        ]
        
        for description in valid_descriptions:
            if description is not None:  # Skip None as it's not allowed
                request = ProjectCreateRequest(
                    name="Test Project",
                    description=description
                )
                assert request.description == description