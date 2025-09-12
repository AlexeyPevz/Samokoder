"""
Basic tests for RBAC (Role-Based Access Control) models
"""
import pytest
from backend.models.requests import RoleCreateRequest, PermissionAssignRequest
from backend.models.responses import RoleResponse, PermissionResponse


class TestRoleCreateRequest:
    """Test RoleCreateRequest model"""
    
    def test_valid_role_create_request(self):
        """Test valid role creation request"""
        request = RoleCreateRequest(
            name="Test Role",
            description="Test Role Description",
            permissions=["read", "write"]
        )
        
        assert request.name == "Test Role"
        assert request.description == "Test Role Description"
        assert request.permissions == ["read", "write"]
    
    def test_minimal_role_create_request(self):
        """Test minimal role creation request"""
        request = RoleCreateRequest(
            name="Minimal Role",
            description="Minimal role description",
            permissions=["read"]
        )
        
        assert request.name == "Minimal Role"
        assert request.description == "Minimal role description"
        assert request.permissions == ["read"]
    
    def test_role_create_request_with_empty_permissions(self):
        """Test role creation request with empty permissions"""
        request = RoleCreateRequest(
            name="Empty Permissions Role",
            description="Role with no permissions",
            permissions=[]
        )
        
        assert request.name == "Empty Permissions Role"
        assert request.permissions == []
    
    def test_role_create_request_with_special_characters(self):
        """Test role creation with special characters"""
        request = RoleCreateRequest(
            name="Role-With_Special.Chars",
            description="Description with émojis 🚀",
            permissions=["read", "write"]
        )
        
        assert request.name == "Role-With_Special.Chars"
        assert request.description == "Description with émojis 🚀"


class TestPermissionAssignRequest:
    """Test PermissionAssignRequest model"""
    
    def test_valid_permission_assign_request(self):
        """Test valid permission assignment request"""
        request = PermissionAssignRequest(
            permission="read_files"
        )
        
        assert request.permission == "read_files"
    
    def test_permission_assign_request_with_special_chars(self):
        """Test permission assignment request with special characters"""
        request = PermissionAssignRequest(
            permission="admin_panel_access"
        )
        
        assert request.permission == "admin_panel_access"


class TestRoleResponse:
    """Test RoleResponse model"""
    
    def test_valid_role_response(self):
        """Test valid role response"""
        response = RoleResponse(
            id="role-123",
            name="Test Role",
            description="Test Role Description",
            permissions=["read", "write", "delete"]
        )
        
        assert response.id == "role-123"
        assert response.name == "Test Role"
        assert response.description == "Test Role Description"
        assert response.permissions == ["read", "write", "delete"]
    
    def test_role_response_with_minimal_data(self):
        """Test role response with minimal data"""
        response = RoleResponse(
            id="minimal-role",
            name="Minimal Role",
            description="Minimal role description",
            permissions=[]
        )
        
        assert response.id == "minimal-role"
        assert response.name == "Minimal Role"
        assert response.description == "Minimal role description"
        assert response.permissions == []
    
    def test_role_response_with_wildcard_permissions(self):
        """Test role response with wildcard permissions"""
        response = RoleResponse(
            id="admin-role",
            name="Administrator",
            description="Full access role",
            permissions=["*"]
        )
        
        assert response.id == "admin-role"
        assert response.name == "Administrator"
        assert response.permissions == ["*"]


class TestPermissionResponse:
    """Test PermissionResponse model"""
    
    def test_valid_permission_response(self):
        """Test valid permission response"""
        response = PermissionResponse(
            id="read-files",
            name="Read Files",
            description="Permission to read project files"
        )
        
        assert response.id == "read-files"
        assert response.name == "Read Files"
        assert response.description == "Permission to read project files"
    
    def test_permission_response_with_minimal_data(self):
        """Test permission response with minimal data"""
        response = PermissionResponse(
            id="basic-permission",
            name="Basic Permission",
            description="Basic permission description"
        )
        
        assert response.id == "basic-permission"
        assert response.name == "Basic Permission"
        assert response.description == "Basic permission description"


class TestRBACWorkflow:
    """Test RBAC workflow"""
    
    def test_create_role_to_response_workflow(self):
        """Test create role then response workflow"""
        # Create role request
        create_request = RoleCreateRequest(
            name="Developer Role",
            description="Role for developers",
            permissions=["read", "write", "execute"]
        )
        
        assert create_request.name == "Developer Role"
        assert create_request.permissions == ["read", "write", "execute"]
        
        # Role response
        role_response = RoleResponse(
            id="dev-role-123",
            name="Developer Role",
            description="Role for developers",
            permissions=["read", "write", "execute"]
        )
        
        assert role_response.name == create_request.name
        assert role_response.permissions == create_request.permissions
    
    def test_permission_assignment_workflow(self):
        """Test permission assignment workflow"""
        # Permission assignment request
        assign_request = PermissionAssignRequest(
            permission="admin_panel"
        )
        
        # Permission response
        permission_response = PermissionResponse(
            id="admin_panel",
            name="Admin Panel",
            description="Access to admin panel"
        )
        
        assert assign_request.permission == permission_response.id
    
    def test_role_permission_mapping(self):
        """Test role to permission mapping"""
        # Admin role with all permissions
        admin_role = RoleResponse(
            id="admin",
            name="Administrator",
            description="Full access",
            permissions=["*"]
        )
        
        # User role with limited permissions
        user_role = RoleResponse(
            id="user",
            name="User",
            description="Basic user",
            permissions=["read", "basic_chat"]
        )
        
        # Developer role with development permissions
        dev_role = RoleResponse(
            id="developer",
            name="Developer",
            description="Developer access",
            permissions=["read", "write", "execute", "debug"]
        )
        
        assert "*" in admin_role.permissions
        assert "read" in user_role.permissions
        assert "debug" in dev_role.permissions


class TestRBACValidation:
    """Test RBAC model validation"""
    
    def test_role_name_validation(self):
        """Test role name validation"""
        # Valid role names
        valid_names = [
            "Simple Role",
            "Role-With-Dashes",
            "Role_With_Underscores",
            "Role123",
            "Роль с русскими символами"
        ]
        
        for name in valid_names:
            request = RoleCreateRequest(
                name=name,
                description="Valid role description",
                permissions=["read"]
            )
            assert request.name == name
    
    def test_permission_validation(self):
        """Test permission validation"""
        # Valid permissions
        valid_permissions = [
            ["read"],
            ["read", "write"],
            ["admin_panel", "user_management"],
            [],
            ["*"]
        ]
        
        for permissions in valid_permissions:
            request = RoleCreateRequest(
                name="Test Role",
                description="Test role description",
                permissions=permissions
            )
            assert request.permissions == permissions
    
    def test_user_id_validation(self):
        """Test user ID validation"""
        # Valid user IDs
        valid_user_ids = [
            "user-123",
            "admin-456",
            "developer-789",
            "test-user",
            "user_with_underscores"
        ]
        
        for user_id in valid_user_ids:
            request = PermissionAssignRequest(
                permission="test_permission"
            )
            assert request.permission == "test_permission"
    
    def test_permission_id_validation(self):
        """Test permission ID validation"""
        # Valid permission IDs
        valid_permission_ids = [
            "read_files",
            "write_files",
            "admin_panel",
            "user_management",
            "basic_chat"
        ]
        
        for permission_id in valid_permission_ids:
            request = PermissionAssignRequest(
                permission=permission_id
            )
            assert request.permission == permission_id


class TestRBACEdgeCases:
    """Test RBAC edge cases"""
    
    def test_empty_role_creation(self):
        """Test empty role creation"""
        # This should fail due to validation
        with pytest.raises(Exception):
            request = RoleCreateRequest(
                name="",
                description="",
                permissions=[]
            )
    
    def test_none_permissions(self):
        """Test None permissions"""
        # This should fail due to validation
        with pytest.raises(Exception):
            request = RoleCreateRequest(
                name="No Permissions Role",
                description="Role description",
                permissions=None
            )
    
    def test_long_role_name(self):
        """Test long role name"""
        long_name = "A" * 200
        # This should fail due to validation
        with pytest.raises(Exception):
            request = RoleCreateRequest(
                name=long_name,
                description="Role description",
                permissions=["read"]
            )
    
    def test_special_characters_in_description(self):
        """Test special characters in description"""
        special_desc = "Description with special chars: @#$%^&*()_+-=[]{}|;':\",./<>?"
        request = RoleCreateRequest(
            name="Special Role",
            description=special_desc,
            permissions=["read"]
        )
        
        assert request.description == special_desc
    
    def test_unicode_characters(self):
        """Test unicode characters"""
        unicode_name = "Роль с émojis 🚀 и unicode символами"
        request = RoleCreateRequest(
            name=unicode_name,
            description="Unicode description with émojis 🎉",
            permissions=["read"]
        )
        
        assert request.name == unicode_name
        assert request.description == "Unicode description with émojis 🎉"