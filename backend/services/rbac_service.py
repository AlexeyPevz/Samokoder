"""
RBAC Service
Сервис для управления ролями и разрешениями
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from uuid import uuid4

logger = logging.getLogger(__name__)

@dataclass
class Role:
    """Роль пользователя"""
    id: str
    name: str
    description: str
    permissions: List[str]

@dataclass
class Permission:
    """Разрешение"""
    id: str
    name: str
    description: str

class RBACService:
    """Сервис для управления ролями и разрешениями"""
    
    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._permissions: Dict[str, Permission] = {}
        self._user_roles: Dict[str, List[str]] = {}
        self._initialize_default_data()
    
    def _initialize_default_data(self):
        """Инициализация ролей и разрешений по умолчанию"""
        # Предопределенные роли
        default_roles = {
            "admin": Role(
                id="admin",
                name="Administrator",
                description="Полный доступ ко всем функциям",
                permissions=["*"]
            ),
            "user": Role(
                id="user",
                name="User", 
                description="Обычный пользователь",
                permissions=["basic_chat", "view_files", "create_projects"]
            ),
            "developer": Role(
                id="developer",
                name="Developer",
                description="Разработчик",
                permissions=["basic_chat", "view_files", "create_projects", "export_projects", "advanced_agents"]
            )
        }
        
        # Предопределенные разрешения
        default_permissions = {
            "basic_chat": Permission("basic_chat", "Базовый чат с AI", "Базовый чат с AI"),
            "view_files": Permission("view_files", "Просмотр файлов проекта", "Просмотр файлов проекта"),
            "create_projects": Permission("create_projects", "Создание проектов", "Создание проектов"),
            "export_projects": Permission("export_projects", "Экспорт проектов", "Экспорт проектов"),
            "advanced_agents": Permission("advanced_agents", "Использование продвинутых агентов", "Использование продвинутых агентов"),
            "custom_models": Permission("custom_models", "Использование пользовательских моделей", "Использование пользовательских моделей"),
            "team_collaboration": Permission("team_collaboration", "Командная работа", "Командная работа"),
            "admin_access": Permission("admin_access", "Административный доступ", "Административный доступ")
        }
        
        # Инициализируем данные
        self._roles.update(default_roles)
        self._permissions.update(default_permissions)
        
        logger.info("RBAC service initialized with default roles and permissions")
    
    def create_role(self, name: str, description: str, permissions: List[str]) -> Role:
        """Создать новую роль"""
        role_id = str(uuid4())
        role = Role(
            id=role_id,
            name=name,
            description=description,
            permissions=permissions
        )
        self._roles[role_id] = role
        logger.info(f"Created role: {name}")
        return role
    
    def get_role(self, role_id: str) -> Optional[Role]:
        """Получить роль по ID"""
        return self._roles.get(role_id)
    
    def get_all_roles(self) -> List[Role]:
        """Получить все роли"""
        return list(self._roles.values())
    
    def update_role(self, role_id: str, name: str = None, description: str = None, permissions: List[str] = None) -> bool:
        """Обновить роль"""
        if role_id not in self._roles:
            return False
        
        role = self._roles[role_id]
        if name is not None:
            role.name = name
        if description is not None:
            role.description = description
        if permissions is not None:
            role.permissions = permissions
        
        logger.info(f"Updated role: {role_id}")
        return True
    
    def delete_role(self, role_id: str) -> bool:
        """Удалить роль"""
        if role_id in self._roles:
            del self._roles[role_id]
            # Удаляем роль у всех пользователей
            for user_id in self._user_roles:
                if role_id in self._user_roles[user_id]:
                    self._user_roles[user_id].remove(role_id)
            logger.info(f"Deleted role: {role_id}")
            return True
        return False
    
    def assign_role_to_user(self, user_id: str, role_id: str) -> bool:
        """Назначить роль пользователю"""
        if role_id not in self._roles:
            return False
        
        if user_id not in self._user_roles:
            self._user_roles[user_id] = []
        
        if role_id not in self._user_roles[user_id]:
            self._user_roles[user_id].append(role_id)
            logger.info(f"Assigned role {role_id} to user {user_id}")
            return True
        
        return False
    
    def remove_role_from_user(self, user_id: str, role_id: str) -> bool:
        """Удалить роль у пользователя"""
        if user_id in self._user_roles and role_id in self._user_roles[user_id]:
            self._user_roles[user_id].remove(role_id)
            logger.info(f"Removed role {role_id} from user {user_id}")
            return True
        return False
    
    def get_user_roles(self, user_id: str) -> List[Role]:
        """Получить роли пользователя"""
        if user_id not in self._user_roles:
            return []
        
        return [self._roles[role_id] for role_id in self._user_roles[user_id] if role_id in self._roles]
    
    def has_permission(self, user_id: str, permission: str) -> bool:
        """Проверить, есть ли у пользователя разрешение"""
        user_roles = self.get_user_roles(user_id)
        
        for role in user_roles:
            if "*" in role.permissions or permission in role.permissions:
                return True
        
        return False
    
    def get_user_permissions(self, user_id: str) -> List[str]:
        """Получить все разрешения пользователя"""
        user_roles = self.get_user_roles(user_id)
        permissions = set()
        
        for role in user_roles:
            if "*" in role.permissions:
                return ["*"]  # Админ имеет все разрешения
            permissions.update(role.permissions)
        
        return list(permissions)

# Глобальный экземпляр сервиса
_rbac_service: Optional[RBACService] = None

def get_rbac_service() -> RBACService:
    """Получить экземпляр RBAC сервиса"""
    global _rbac_service
    if _rbac_service is None:
        _rbac_service = RBACService()
    return _rbac_service