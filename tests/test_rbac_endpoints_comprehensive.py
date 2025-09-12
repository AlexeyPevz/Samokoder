"""
Комплексные тесты для RBAC endpoints
Покрытие: 34% → 90%+
"""

import pytest
import uuid
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException, status
from datetime import datetime

from backend.api.rbac import (
    router,
    get_roles,
    get_permissions,
    get_user_roles,
    assign_role,
    remove_role,
    check_permission,
    init_default_roles,
    roles,
    permissions,
    user_roles,
    DEFAULT_ROLES,
    DEFAULT_PERMISSIONS
)
from backend.models.requests import RoleCreateRequest, PermissionAssignRequest
from backend.models.responses import RoleResponse, PermissionResponse


class TestRBACEndpoints:
    """Тесты для RBAC endpoints"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Настройка для каждого теста"""
        # Очищаем временное хранилище
        global roles, permissions, user_roles
        roles.clear()
        permissions.clear()
        user_roles.clear()
        
        # Восстанавливаем дефолтные роли
        init_default_roles()
    
    @pytest.fixture
    def mock_current_user(self):
        return {
            "id": str(uuid.uuid4()),
            "email": "test@example.com",
            "is_active": True
        }
    
    @pytest.fixture
    def mock_admin_user(self):
        return {
            "id": str(uuid.uuid4()),
            "email": "admin@example.com",
            "is_active": True
        }
    
    @pytest.fixture
    def mock_user_roles(self):
        return ["user", "developer"]
    
    # === GET ROLES ===
    
    @pytest.mark.asyncio
    async def test_get_roles_success(self, mock_current_user):
        """Тест успешного получения списка ролей"""
        result = await get_roles(mock_current_user)
        
        assert isinstance(result, list)
        assert len(result) == len(DEFAULT_ROLES)
        
        # Проверяем, что все роли присутствуют
        role_ids = [role.id for role in result]
        assert "admin" in role_ids
        assert "user" in role_ids
        assert "developer" in role_ids
        
        # Проверяем структуру ответа
        admin_role = next(role for role in result if role.id == "admin")
        assert admin_role.name == "Administrator"
        assert admin_role.description == "Полный доступ ко всем функциям"
        assert "*" in admin_role.permissions
    
    @pytest.mark.asyncio
    async def test_get_roles_empty_roles(self, mock_current_user):
        """Тест получения ролей когда ролей нет"""
        global roles
        roles.clear()
        
        result = await get_roles(mock_current_user)
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_get_roles_exception(self, mock_current_user):
        """Тест обработки исключения при получении ролей"""
        # Создаем мокирующий словарь с методом items, который вызывает исключение
        mock_roles = Mock()
        mock_roles.items.side_effect = Exception("Database error")
        
        with patch('backend.api.rbac.roles', mock_roles):
            with pytest.raises(HTTPException) as exc_info:
                await get_roles(mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка получения ролей" in str(exc_info.value.detail)
    
    # === GET PERMISSIONS ===
    
    @pytest.mark.asyncio
    async def test_get_permissions_success(self, mock_current_user):
        """Тест успешного получения списка разрешений"""
        result = await get_permissions(mock_current_user)
        
        assert isinstance(result, list)
        assert len(result) == len(DEFAULT_PERMISSIONS)
        
        # Проверяем, что все разрешения присутствуют
        permission_ids = [perm.id for perm in result]
        assert "basic_chat" in permission_ids
        assert "view_files" in permission_ids
        assert "create_projects" in permission_ids
        
        # Проверяем структуру ответа
        basic_chat_perm = next(perm for perm in result if perm.id == "basic_chat")
        assert basic_chat_perm.name == "Basic Chat"
        assert basic_chat_perm.description == "Базовый чат с AI"
    
    @pytest.mark.asyncio
    async def test_get_permissions_empty_permissions(self, mock_current_user):
        """Тест получения разрешений когда разрешений нет"""
        global permissions
        permissions.clear()
        
        result = await get_permissions(mock_current_user)
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_get_permissions_exception(self, mock_current_user):
        """Тест обработки исключения при получении разрешений"""
        # Создаем мокирующий словарь с методом items, который вызывает исключение
        mock_permissions = Mock()
        mock_permissions.items.side_effect = Exception("Database error")
        
        with patch('backend.api.rbac.permissions', mock_permissions):
            with pytest.raises(HTTPException) as exc_info:
                await get_permissions(mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка получения разрешений" in str(exc_info.value.detail)
    
    # === GET USER ROLES ===
    
    @pytest.mark.asyncio
    async def test_get_user_roles_own_roles(self, mock_current_user):
        """Тест получения собственных ролей пользователя"""
        user_id = mock_current_user["id"]
        user_roles[user_id] = ["user", "developer"]
        
        result = await get_user_roles(user_id, mock_current_user)
        
        assert result == ["user", "developer"]
    
    @pytest.mark.asyncio
    async def test_get_user_roles_default_role(self, mock_current_user):
        """Тест получения ролей пользователя без назначенных ролей"""
        user_id = mock_current_user["id"]
        
        result = await get_user_roles(user_id, mock_current_user)
        
        assert result == ["user"]
    
    @pytest.mark.asyncio
    async def test_get_user_roles_admin_access(self, mock_admin_user, mock_current_user):
        """Тест получения ролей пользователя администратором"""
        target_user_id = str(uuid.uuid4())
        user_roles[mock_admin_user["id"]] = ["admin"]
        user_roles[target_user_id] = ["user", "developer"]
        
        result = await get_user_roles(target_user_id, mock_admin_user)
        
        assert result == ["user", "developer"]
    
    @pytest.mark.asyncio
    async def test_get_user_roles_forbidden_access(self, mock_current_user):
        """Тест получения ролей другого пользователя без прав"""
        target_user_id = str(uuid.uuid4())
        user_roles[target_user_id] = ["admin"]
        
        with pytest.raises(HTTPException) as exc_info:
            await get_user_roles(target_user_id, mock_current_user)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Недостаточно прав для просмотра ролей пользователя" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_user_roles_exception(self, mock_current_user):
        """Тест обработки исключения при получении ролей пользователя"""
        user_id = mock_current_user["id"]
        
        # Создаем мокирующий словарь с методом get, который вызывает исключение
        mock_user_roles = Mock()
        mock_user_roles.get.side_effect = Exception("Database error")
        
        with patch('backend.api.rbac.user_roles', mock_user_roles):
            with pytest.raises(HTTPException) as exc_info:
                await get_user_roles(user_id, mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка получения ролей пользователя" in str(exc_info.value.detail)
    
    # === ASSIGN ROLE ===
    
    @pytest.mark.asyncio
    async def test_assign_role_success_new_user(self, mock_admin_user):
        """Тест успешного назначения роли новому пользователю"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        role_id = "developer"
        
        result = await assign_role(target_user_id, role_id, mock_admin_user)
        
        assert result["message"] == f"Роль {role_id} назначена пользователю {target_user_id}"
        assert role_id in user_roles[target_user_id]
    
    @pytest.mark.asyncio
    async def test_assign_role_success_existing_user(self, mock_admin_user):
        """Тест успешного назначения роли существующему пользователю"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        user_roles[target_user_id] = ["user"]
        role_id = "developer"
        
        result = await assign_role(target_user_id, role_id, mock_admin_user)
        
        assert result["message"] == f"Роль {role_id} назначена пользователю {target_user_id}"
        assert role_id in user_roles[target_user_id]
        assert "user" in user_roles[target_user_id]  # Старая роль должна остаться
    
    @pytest.mark.asyncio
    async def test_assign_role_duplicate_role(self, mock_admin_user):
        """Тест назначения уже существующей роли"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        user_roles[target_user_id] = ["developer"]
        role_id = "developer"
        
        result = await assign_role(target_user_id, role_id, mock_admin_user)
        
        assert result["message"] == f"Роль {role_id} назначена пользователю {target_user_id}"
        # Роль не должна дублироваться
        assert user_roles[target_user_id].count(role_id) == 1
    
    @pytest.mark.asyncio
    async def test_assign_role_forbidden_non_admin(self, mock_current_user):
        """Тест назначения роли пользователем без прав администратора"""
        target_user_id = str(uuid.uuid4())
        role_id = "developer"
        
        with pytest.raises(HTTPException) as exc_info:
            await assign_role(target_user_id, role_id, mock_current_user)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Недостаточно прав для назначения ролей" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_assign_role_role_not_found(self, mock_admin_user):
        """Тест назначения несуществующей роли"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        role_id = "nonexistent_role"
        
        with pytest.raises(HTTPException) as exc_info:
            await assign_role(target_user_id, role_id, mock_admin_user)
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "Роль не найдена" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_assign_role_exception(self, mock_admin_user):
        """Тест обработки исключения при назначении роли"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        role_id = "developer"
        
        # Создаем мокирующий словарь с методом get, который вызывает исключение
        mock_user_roles = Mock()
        mock_user_roles.get.return_value = ["admin"]
        mock_user_roles.__contains__ = Mock(side_effect=Exception("Database error"))
        
        with patch('backend.api.rbac.user_roles', mock_user_roles):
            with pytest.raises(HTTPException) as exc_info:
                await assign_role(target_user_id, role_id, mock_admin_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка назначения роли" in str(exc_info.value.detail)
    
    # === REMOVE ROLE ===
    
    @pytest.mark.asyncio
    async def test_remove_role_success(self, mock_admin_user):
        """Тест успешного удаления роли у пользователя"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        user_roles[target_user_id] = ["user", "developer"]
        role_id = "developer"
        
        result = await remove_role(target_user_id, role_id, mock_admin_user)
        
        assert result["message"] == f"Роль {role_id} удалена у пользователя {target_user_id}"
        assert role_id not in user_roles[target_user_id]
        assert "user" in user_roles[target_user_id]  # Другие роли должны остаться
    
    @pytest.mark.asyncio
    async def test_remove_role_forbidden_non_admin(self, mock_current_user):
        """Тест удаления роли пользователем без прав администратора"""
        target_user_id = str(uuid.uuid4())
        role_id = "developer"
        
        with pytest.raises(HTTPException) as exc_info:
            await remove_role(target_user_id, role_id, mock_current_user)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Недостаточно прав для удаления ролей" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_remove_role_role_not_found(self, mock_admin_user):
        """Тест удаления несуществующей роли у пользователя"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        user_roles[target_user_id] = ["user"]
        role_id = "developer"
        
        with pytest.raises(HTTPException) as exc_info:
            await remove_role(target_user_id, role_id, mock_admin_user)
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Роль не найдена у пользователя" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_remove_role_user_not_found(self, mock_admin_user):
        """Тест удаления роли у несуществующего пользователя"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        role_id = "developer"
        
        with pytest.raises(HTTPException) as exc_info:
            await remove_role(target_user_id, role_id, mock_admin_user)
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Роль не найдена у пользователя" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_remove_role_exception(self, mock_admin_user):
        """Тест обработки исключения при удалении роли"""
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = str(uuid.uuid4())
        role_id = "developer"
        
        # Создаем мокирующий словарь с методом get, который вызывает исключение
        mock_user_roles = Mock()
        mock_user_roles.get.side_effect = Exception("Database error")
        
        with patch('backend.api.rbac.user_roles', mock_user_roles):
            with pytest.raises(HTTPException) as exc_info:
                await remove_role(target_user_id, role_id, mock_admin_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка удаления роли" in str(exc_info.value.detail)
    
    # === CHECK PERMISSION ===
    
    @pytest.mark.asyncio
    async def test_check_permission_admin_all_permissions(self, mock_current_user):
        """Тест проверки разрешения для администратора"""
        user_id = mock_current_user["id"]
        user_roles[user_id] = ["admin"]
        
        result = await check_permission("basic_chat", mock_current_user)
        
        assert result["has_permission"] is True
        assert result["permission"] == "basic_chat"
        assert result["granted_by_role"] == "admin"
    
    @pytest.mark.asyncio
    async def test_check_permission_user_has_permission(self, mock_current_user):
        """Тест проверки разрешения для пользователя с соответствующими правами"""
        user_id = mock_current_user["id"]
        user_roles[user_id] = ["user"]
        
        result = await check_permission("basic_chat", mock_current_user)
        
        assert result["has_permission"] is True
        assert result["permission"] == "basic_chat"
        assert result["granted_by_role"] == "user"
    
    @pytest.mark.asyncio
    async def test_check_permission_user_no_permission(self, mock_current_user):
        """Тест проверки разрешения для пользователя без соответствующих прав"""
        user_id = mock_current_user["id"]
        user_roles[user_id] = ["user"]
        
        result = await check_permission("admin_panel", mock_current_user)
        
        assert result["has_permission"] is False
        assert result["permission"] == "admin_panel"
        assert result["user_roles"] == ["user"]
    
    @pytest.mark.asyncio
    async def test_check_permission_multiple_roles(self, mock_current_user):
        """Тест проверки разрешения для пользователя с несколькими ролями"""
        user_id = mock_current_user["id"]
        user_roles[user_id] = ["user", "developer"]
        
        result = await check_permission("export_projects", mock_current_user)
        
        assert result["has_permission"] is True
        assert result["permission"] == "export_projects"
        assert result["granted_by_role"] == "developer"
    
    @pytest.mark.asyncio
    async def test_check_permission_default_user_role(self, mock_current_user):
        """Тест проверки разрешения для пользователя с ролью по умолчанию"""
        user_id = mock_current_user["id"]
        # Не назначаем роли, должна использоваться роль по умолчанию "user"
        
        result = await check_permission("basic_chat", mock_current_user)
        
        assert result["has_permission"] is True
        assert result["permission"] == "basic_chat"
        assert result["granted_by_role"] == "user"
    
    @pytest.mark.asyncio
    async def test_check_permission_exception(self, mock_current_user):
        """Тест обработки исключения при проверке разрешения"""
        # Создаем мокирующий словарь с методом get, который вызывает исключение
        mock_user_roles = Mock()
        mock_user_roles.get.side_effect = Exception("Database error")
        
        with patch('backend.api.rbac.user_roles', mock_user_roles):
            with pytest.raises(HTTPException) as exc_info:
                await check_permission("basic_chat", mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка проверки разрешения" in str(exc_info.value.detail)
    
    # === INIT DEFAULT ROLES ===
    
    def test_init_default_roles(self):
        """Тест инициализации ролей по умолчанию"""
        global roles, permissions
        roles.clear()
        permissions.clear()
        
        init_default_roles()
        
        # Проверяем, что все роли добавлены
        assert len(roles) == len(DEFAULT_ROLES)
        assert "admin" in roles
        assert "user" in roles
        assert "developer" in roles
        
        # Проверяем, что все разрешения добавлены
        assert len(permissions) == len(DEFAULT_PERMISSIONS)
        assert "basic_chat" in permissions
        assert "view_files" in permissions
        
        # Проверяем структуру данных
        admin_role = roles["admin"]
        assert admin_role["name"] == "Administrator"
        assert "*" in admin_role["permissions"]
        
        basic_chat_perm = permissions["basic_chat"]
        assert basic_chat_perm["name"] == "Basic Chat"
        assert basic_chat_perm["description"] == "Базовый чат с AI"
    
    # === INTEGRATION TESTS ===
    
    @pytest.mark.asyncio
    async def test_full_rbac_workflow(self, mock_admin_user, mock_current_user):
        """Тест полного workflow RBAC системы"""
        # 1. Админ назначает роль пользователю
        user_roles[mock_admin_user["id"]] = ["admin"]
        target_user_id = mock_current_user["id"]
        
        assign_result = await assign_role(target_user_id, "developer", mock_admin_user)
        assert "developer" in user_roles[target_user_id]
        
        # 2. Проверяем, что у пользователя есть роль
        user_roles_result = await get_user_roles(target_user_id, mock_admin_user)
        assert "developer" in user_roles_result
        
        # 3. Проверяем разрешения пользователя
        permission_result = await check_permission("export_projects", mock_current_user)
        assert permission_result["has_permission"] is True
        assert permission_result["granted_by_role"] == "developer"
        
        # 4. Админ удаляет роль
        remove_result = await remove_role(target_user_id, "developer", mock_admin_user)
        assert "developer" not in user_roles[target_user_id]
        
        # 5. Проверяем, что разрешение больше нет
        permission_result = await check_permission("export_projects", mock_current_user)
        assert permission_result["has_permission"] is False