"""
Упрощенные тесты для RBAC (34% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI

from backend.api.rbac import router, roles, permissions, user_roles, DEFAULT_ROLES, DEFAULT_PERMISSIONS


class TestRBACEndpoints:
    """Тесты для RBAC endpoints"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.app = FastAPI()
        self.app.include_router(router)
        self.client = TestClient(self.app)
        
        # Очищаем хранилища
        roles.clear()
        permissions.clear()
        user_roles.clear()
        
        # Инициализируем предопределенные роли
        roles.update(DEFAULT_ROLES)

    def test_init_default_roles(self):
        """Тест инициализации предопределенных ролей"""
        assert "admin" in DEFAULT_ROLES
        assert "user" in DEFAULT_ROLES
        assert "developer" in DEFAULT_ROLES
        
        assert DEFAULT_ROLES["admin"]["permissions"] == ["*"]
        assert "basic_chat" in DEFAULT_ROLES["user"]["permissions"]
        assert "advanced_agents" in DEFAULT_ROLES["developer"]["permissions"]

    def test_init_default_permissions(self):
        """Тест инициализации предопределенных разрешений"""
        assert "basic_chat" in DEFAULT_PERMISSIONS
        assert "view_files" in DEFAULT_PERMISSIONS
        assert "create_projects" in DEFAULT_PERMISSIONS
        assert "export_projects" in DEFAULT_PERMISSIONS

    @patch('backend.api.rbac.get_current_user')
    def test_get_roles_success(self, mock_get_user):
        """Тест получения списка ролей - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Act
        response = self.client.get("/roles")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3  # admin, user, developer

    @patch('backend.api.rbac.get_current_user')
    def test_get_roles_unauthorized(self, mock_get_user):
        """Тест получения списка ролей - неавторизован"""
        # Arrange
        mock_get_user.side_effect = Exception("Unauthorized")
        
        # Act
        response = self.client.get("/roles")
        
        # Assert
        assert response.status_code == 401

    @patch('backend.api.rbac.get_current_user')
    def test_create_role_success(self, mock_get_user):
        """Тест создания роли - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        role_data = {
            "name": "Test Role",
            "description": "Test role description",
            "permissions": ["basic_chat", "view_files"]
        }
        
        # Act
        response = self.client.post("/roles", json=role_data)
        
        # Assert
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Role"
        assert data["description"] == "Test role description"
        assert "id" in data

    @patch('backend.api.rbac.get_current_user')
    def test_create_role_duplicate_name(self, mock_get_user):
        """Тест создания роли - дублирующееся имя"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        role_data = {
            "name": "admin",  # Уже существует
            "description": "Duplicate role",
            "permissions": ["basic_chat"]
        }
        
        # Act
        response = self.client.post("/roles", json=role_data)
        
        # Assert
        assert response.status_code == 400
        assert "Role with this name already exists" in response.json()["detail"]

    @patch('backend.api.rbac.get_current_user')
    def test_get_role_success(self, mock_get_user):
        """Тест получения роли по ID - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Act
        response = self.client.get("/roles/admin")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "admin"
        assert data["name"] == "Administrator"

    @patch('backend.api.rbac.get_current_user')
    def test_get_role_not_found(self, mock_get_user):
        """Тест получения роли по ID - не найдена"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Act
        response = self.client.get("/roles/nonexistent")
        
        # Assert
        assert response.status_code == 404
        assert "Role not found" in response.json()["detail"]

    @patch('backend.api.rbac.get_current_user')
    def test_update_role_success(self, mock_get_user):
        """Тест обновления роли - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        update_data = {
            "name": "Updated Admin",
            "description": "Updated description",
            "permissions": ["*"]
        }
        
        # Act
        response = self.client.put("/roles/admin", json=update_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Admin"
        assert data["description"] == "Updated description"

    @patch('backend.api.rbac.get_current_user')
    def test_delete_role_success(self, mock_get_user):
        """Тест удаления роли - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Создаем тестовую роль
        role_data = {
            "name": "Test Role",
            "description": "Test role",
            "permissions": ["basic_chat"]
        }
        create_response = self.client.post("/roles", json=role_data)
        role_id = create_response.json()["id"]
        
        # Act
        response = self.client.delete(f"/roles/{role_id}")
        
        # Assert
        assert response.status_code == 204

    @patch('backend.api.rbac.get_current_user')
    def test_delete_role_not_found(self, mock_get_user):
        """Тест удаления роли - не найдена"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Act
        response = self.client.delete("/roles/nonexistent")
        
        # Assert
        assert response.status_code == 404
        assert "Role not found" in response.json()["detail"]

    @patch('backend.api.rbac.get_current_user')
    def test_assign_role_success(self, mock_get_user):
        """Тест назначения роли пользователю - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        assign_data = {
            "user_id": "user456",
            "role_id": "user"
        }
        
        # Act
        response = self.client.post("/roles/assign", json=assign_data)
        
        # Assert
        assert response.status_code == 200
        assert "user456" in user_roles
        assert "user" in user_roles["user456"]

    @patch('backend.api.rbac.get_current_user')
    def test_assign_role_invalid_role(self, mock_get_user):
        """Тест назначения роли пользователю - невалидная роль"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        assign_data = {
            "user_id": "user456",
            "role_id": "nonexistent"
        }
        
        # Act
        response = self.client.post("/roles/assign", json=assign_data)
        
        # Assert
        assert response.status_code == 404
        assert "Role not found" in response.json()["detail"]

    @patch('backend.api.rbac.get_current_user')
    def test_revoke_role_success(self, mock_get_user):
        """Тест отзыва роли у пользователя - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Сначала назначаем роль
        user_roles["user456"] = ["user"]
        
        revoke_data = {
            "user_id": "user456",
            "role_id": "user"
        }
        
        # Act
        response = self.client.post("/roles/revoke", json=revoke_data)
        
        # Assert
        assert response.status_code == 200
        assert "user456" not in user_roles

    @patch('backend.api.rbac.get_current_user')
    def test_revoke_role_user_not_found(self, mock_get_user):
        """Тест отзыва роли у пользователя - пользователь не найден"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        revoke_data = {
            "user_id": "nonexistent",
            "role_id": "user"
        }
        
        # Act
        response = self.client.post("/roles/revoke", json=revoke_data)
        
        # Assert
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @patch('backend.api.rbac.get_current_user')
    def test_get_user_roles_success(self, mock_get_user):
        """Тест получения ролей пользователя - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        user_roles["user456"] = ["user", "developer"]
        
        # Act
        response = self.client.get("/users/user456/roles")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "user456" in data
        assert len(data["user456"]) == 2
        assert "user" in data["user456"]
        assert "developer" in data["user456"]

    @patch('backend.api.rbac.get_current_user')
    def test_get_user_roles_not_found(self, mock_get_user):
        """Тест получения ролей пользователя - пользователь не найден"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Act
        response = self.client.get("/users/nonexistent/roles")
        
        # Assert
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @patch('backend.api.rbac.get_current_user')
    def test_check_permission_success(self, mock_get_user):
        """Тест проверки разрешения - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        user_roles["user456"] = ["admin"]  # admin имеет все разрешения
        
        # Act
        response = self.client.get("/users/user456/permissions/basic_chat")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["has_permission"] is True

    @patch('backend.api.rbac.get_current_user')
    def test_check_permission_denied(self, mock_get_user):
        """Тест проверки разрешения - отказано"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        user_roles["user456"] = ["user"]  # user не имеет advanced_agents
        
        # Act
        response = self.client.get("/users/user456/permissions/advanced_agents")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["has_permission"] is False

    @patch('backend.api.rbac.get_current_user')
    def test_get_permissions_success(self, mock_get_user):
        """Тест получения списка разрешений - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Act
        response = self.client.get("/permissions")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    @patch('backend.api.rbac.get_current_user')
    def test_create_permission_success(self, mock_get_user):
        """Тест создания разрешения - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        permission_data = {
            "name": "test_permission",
            "description": "Test permission description"
        }
        
        # Act
        response = self.client.post("/permissions", json=permission_data)
        
        # Assert
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test_permission"
        assert data["description"] == "Test permission description"
        assert "id" in data

    @patch('backend.api.rbac.get_current_user')
    def test_create_permission_duplicate_name(self, mock_get_user):
        """Тест создания разрешения - дублирующееся имя"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        permission_data = {
            "name": "basic_chat",  # Уже существует
            "description": "Duplicate permission"
        }
        
        # Act
        response = self.client.post("/permissions", json=permission_data)
        
        # Assert
        assert response.status_code == 400
        assert "Permission with this name already exists" in response.json()["detail"]

    @patch('backend.api.rbac.get_current_user')
    def test_delete_permission_success(self, mock_get_user):
        """Тест удаления разрешения - успех"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Создаем тестовое разрешение
        permission_data = {
            "name": "test_permission",
            "description": "Test permission"
        }
        create_response = self.client.post("/permissions", json=permission_data)
        permission_id = create_response.json()["id"]
        
        # Act
        response = self.client.delete(f"/permissions/{permission_id}")
        
        # Assert
        assert response.status_code == 204

    @patch('backend.api.rbac.get_current_user')
    def test_delete_permission_not_found(self, mock_get_user):
        """Тест удаления разрешения - не найдено"""
        # Arrange
        mock_user = Mock()
        mock_user.id = "user123"
        mock_get_user.return_value = mock_user
        
        # Act
        response = self.client.delete("/permissions/nonexistent")
        
        # Assert
        assert response.status_code == 404
        assert "Permission not found" in response.json()["detail"]

    def test_roles_storage(self):
        """Тест хранилища ролей"""
        # Arrange & Act
        roles["test_role"] = {
            "id": "test_role",
            "name": "Test Role",
            "description": "Test",
            "permissions": ["basic_chat"]
        }
        
        # Assert
        assert "test_role" in roles
        assert roles["test_role"]["name"] == "Test Role"

    def test_permissions_storage(self):
        """Тест хранилища разрешений"""
        # Arrange & Act
        permissions["test_permission"] = {
            "id": "test_permission",
            "name": "test_permission",
            "description": "Test permission"
        }
        
        # Assert
        assert "test_permission" in permissions
        assert permissions["test_permission"]["name"] == "test_permission"

    def test_user_roles_storage(self):
        """Тест хранилища ролей пользователей"""
        # Arrange & Act
        user_roles["user123"] = ["admin", "developer"]
        
        # Assert
        assert "user123" in user_roles
        assert "admin" in user_roles["user123"]
        assert "developer" in user_roles["user123"]