"""
Тесты безопасности контроля доступа - рефакторированная версия
Разделены на специализированные классы для лучшей организации
"""

import pytest
from security_patches.asvs_v4_access_control_p0_fixes import AccessControlSecurity

class BaseAccessControlTest:
    """Базовый класс для тестов контроля доступа"""
    
    @pytest.fixture
    def access_control(self):
        """Создать экземпляр AccessControlSecurity"""
        return AccessControlSecurity()

class TestPermissionChecks(BaseAccessControlTest):
    """Тесты проверки разрешений"""
    
    def test_permission_check_success(self, access_control):
        """V4.1.1: Тест успешной проверки разрешений"""
        # Free пользователь может читать проекты
        assert access_control.check_permission("free", "project", "read") is True
        
        # Professional пользователь может удалять файлы
        assert access_control.check_permission("professional", "file", "delete") is True
        
        # Enterprise пользователь может администрировать
        assert access_control.check_permission("enterprise", "admin", "delete") is True

    def test_permission_check_failure(self, access_control):
        """V4.1.1: Тест неудачной проверки разрешений"""
        # Free пользователь не может удалять проекты
        assert access_control.check_permission("free", "project", "delete") is False
        
        # Starter пользователь не может администрировать
        assert access_control.check_permission("starter", "admin", "write") is False
        
        # Неизвестная роль
        assert access_control.check_permission("unknown_role", "project", "read") is False

class TestRoleManagement(BaseAccessControlTest):
    """Тесты управления ролями"""
    
    def test_role_assignment(self, access_control):
        """V4.1.2: Тест назначения ролей"""
        user_id = "user123"
        role = "professional"
        
        # Назначаем роль
        result = access_control.assign_role(user_id, role)
        assert result is True
        
        # Проверяем, что роль назначена
        user_roles = access_control.get_user_roles(user_id)
        assert role in user_roles

    def test_role_removal(self, access_control):
        """V4.1.2: Тест удаления ролей"""
        user_id = "user123"
        role = "professional"
        
        # Сначала назначаем роль
        access_control.assign_role(user_id, role)
        
        # Удаляем роль
        result = access_control.remove_role(user_id, role)
        assert result is True
        
        # Проверяем, что роль удалена
        user_roles = access_control.get_user_roles(user_id)
        assert role not in user_roles

class TestResourceAccess(BaseAccessControlTest):
    """Тесты доступа к ресурсам"""
    
    def test_resource_access_control(self, access_control):
        """V4.1.3: Тест контроля доступа к ресурсам"""
        user_id = "user123"
        resource_id = "project456"
        
        # Назначаем роль
        access_control.assign_role(user_id, "professional")
        
        # Проверяем доступ к ресурсу
        has_access = access_control.check_resource_access(user_id, resource_id, "read")
        assert has_access is True

class TestAccessControlSecurity(BaseAccessControlTest):
    """Основные тесты безопасности контроля доступа"""
    
    def test_access_control_initialization(self, access_control):
        """V4.1.4: Тест инициализации контроля доступа"""
        assert hasattr(access_control, 'permissions')
        assert hasattr(access_control, 'user_roles')
        assert isinstance(access_control.permissions, dict)
        assert isinstance(access_control.user_roles, dict)