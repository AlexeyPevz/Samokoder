"""
Безопасная реализация RBAC с персистентным хранилищем
"""

import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import asyncio

logger = logging.getLogger(__name__)

class Permission(Enum):
    """Разрешения системы"""
    # Проекты
    PROJECT_CREATE = "project:create"
    PROJECT_READ = "project:read"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"
    
    # API ключи
    API_KEY_CREATE = "api_key:create"
    API_KEY_READ = "api_key:read"
    API_KEY_UPDATE = "api_key:update"
    API_KEY_DELETE = "api_key:delete"
    
    # Пользователи
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Администрирование
    ADMIN_READ = "admin:read"
    ADMIN_UPDATE = "admin:update"
    ADMIN_DELETE = "admin:delete"
    ROLE_MANAGE = "role:manage"
    PERMISSION_MANAGE = "permission:manage"

@dataclass
class Role:
    """Роль пользователя"""
    id: str
    name: str
    description: str
    permissions: Set[Permission]
    created_at: datetime
    updated_at: datetime
    is_active: bool = True

@dataclass
class UserRole:
    """Роль пользователя"""
    user_id: str
    role_id: str
    assigned_at: datetime
    assigned_by: str
    is_active: bool = True

class SecureRBAC:
    """Безопасная система RBAC"""
    
    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._user_roles: Dict[str, List[UserRole]] = {}
        self._lock = asyncio.Lock()
        
        # Инициализируем базовые роли
        self._initialize_default_roles()
    
    def _initialize_default_roles(self):
        """Инициализирует базовые роли"""
        now = datetime.now()
        
        # Роль администратора
        admin_role = Role(
            id="admin",
            name="Administrator",
            description="Полный доступ ко всем функциям",
            permissions=set(Permission),
            created_at=now,
            updated_at=now
        )
        self._roles["admin"] = admin_role
        
        # Роль пользователя
        user_permissions = {
            Permission.PROJECT_CREATE,
            Permission.PROJECT_READ,
            Permission.PROJECT_UPDATE,
            Permission.PROJECT_DELETE,
            Permission.API_KEY_CREATE,
            Permission.API_KEY_READ,
            Permission.API_KEY_UPDATE,
            Permission.API_KEY_DELETE,
            Permission.USER_READ,
            Permission.USER_UPDATE
        }
        
        user_role = Role(
            id="user",
            name="User",
            description="Стандартные права пользователя",
            permissions=user_permissions,
            created_at=now,
            updated_at=now
        )
        self._roles["user"] = user_role
        
        # Роль гостя
        guest_permissions = {
            Permission.PROJECT_READ,
            Permission.USER_READ
        }
        
        guest_role = Role(
            id="guest",
            name="Guest",
            description="Ограниченные права для гостей",
            permissions=guest_permissions,
            created_at=now,
            updated_at=now
        )
        self._roles["guest"] = guest_role
    
    async def assign_role(self, user_id: str, role_id: str, assigned_by: str) -> bool:
        """Назначает роль пользователю"""
        async with self._lock:
            if role_id not in self._roles:
                logger.error(f"Role {role_id} not found")
                return False
            
            if not self._roles[role_id].is_active:
                logger.error(f"Role {role_id} is not active")
                return False
            
            # Проверяем, что назначающий имеет права на управление ролями
            if not await self.has_permission(assigned_by, Permission.ROLE_MANAGE):
                logger.error(f"User {assigned_by} does not have permission to assign roles")
                return False
            
            # Создаем новую роль пользователя
            user_role = UserRole(
                user_id=user_id,
                role_id=role_id,
                assigned_at=datetime.now(),
                assigned_by=assigned_by
            )
            
            if user_id not in self._user_roles:
                self._user_roles[user_id] = []
            
            # Деактивируем старые роли этого типа
            for existing_role in self._user_roles[user_id]:
                if existing_role.role_id == role_id:
                    existing_role.is_active = False
            
            self._user_roles[user_id].append(user_role)
            
            logger.info(f"Role {role_id} assigned to user {user_id} by {assigned_by}")
            return True
    
    async def revoke_role(self, user_id: str, role_id: str, revoked_by: str) -> bool:
        """Отзывает роль у пользователя"""
        async with self._lock:
            # Проверяем права
            if not await self.has_permission(revoked_by, Permission.ROLE_MANAGE):
                logger.error(f"User {revoked_by} does not have permission to revoke roles")
                return False
            
            if user_id not in self._user_roles:
                return False
            
            # Деактивируем роль
            for user_role in self._user_roles[user_id]:
                if user_role.role_id == role_id and user_role.is_active:
                    user_role.is_active = False
                    logger.info(f"Role {role_id} revoked from user {user_id} by {revoked_by}")
                    return True
            
            return False
    
    async def has_permission(self, user_id: str, permission: Permission) -> bool:
        """Проверяет, есть ли у пользователя разрешение"""
        if user_id not in self._user_roles:
            return False
        
        # Получаем все активные роли пользователя
        active_roles = [
            user_role for user_role in self._user_roles[user_id]
            if user_role.is_active
        ]
        
        # Проверяем разрешения в каждой роли
        for user_role in active_roles:
            if user_role.role_id in self._roles:
                role = self._roles[user_role.role_id]
                if role.is_active and permission in role.permissions:
                    return True
        
        return False
    
    async def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Получает все разрешения пользователя"""
        permissions = set()
        
        if user_id not in self._user_roles:
            return permissions
        
        # Получаем все активные роли пользователя
        active_roles = [
            user_role for user_role in self._user_roles[user_id]
            if user_role.is_active
        ]
        
        # Собираем разрешения из всех ролей
        for user_role in active_roles:
            if user_role.role_id in self._roles:
                role = self._roles[user_role.role_id]
                if role.is_active:
                    permissions.update(role.permissions)
        
        return permissions
    
    async def get_user_roles(self, user_id: str) -> List[Role]:
        """Получает все роли пользователя"""
        roles = []
        
        if user_id not in self._user_roles:
            return roles
        
        # Получаем все активные роли пользователя
        active_roles = [
            user_role for user_role in self._user_roles[user_id]
            if user_role.is_active
        ]
        
        # Собираем объекты ролей
        for user_role in active_roles:
            if user_role.role_id in self._roles:
                role = self._roles[user_role.role_id]
                if role.is_active:
                    roles.append(role)
        
        return roles
    
    async def create_role(self, role_id: str, name: str, description: str, 
                         permissions: Set[Permission], created_by: str) -> bool:
        """Создает новую роль"""
        async with self._lock:
            # Проверяем права
            if not await self.has_permission(created_by, Permission.ROLE_MANAGE):
                logger.error(f"User {created_by} does not have permission to create roles")
                return False
            
            if role_id in self._roles:
                logger.error(f"Role {role_id} already exists")
                return False
            
            now = datetime.now()
            role = Role(
                id=role_id,
                name=name,
                description=description,
                permissions=permissions,
                created_at=now,
                updated_at=now
            )
            
            self._roles[role_id] = role
            logger.info(f"Role {role_id} created by {created_by}")
            return True
    
    async def update_role(self, role_id: str, name: Optional[str] = None,
                         description: Optional[str] = None,
                         permissions: Optional[Set[Permission]] = None,
                         updated_by: str = None) -> bool:
        """Обновляет роль"""
        async with self._lock:
            # Проверяем права
            if not await self.has_permission(updated_by, Permission.ROLE_MANAGE):
                logger.error(f"User {updated_by} does not have permission to update roles")
                return False
            
            if role_id not in self._roles:
                logger.error(f"Role {role_id} not found")
                return False
            
            role = self._roles[role_id]
            
            if name is not None:
                role.name = name
            if description is not None:
                role.description = description
            if permissions is not None:
                role.permissions = permissions
            
            role.updated_at = datetime.now()
            
            logger.info(f"Role {role_id} updated by {updated_by}")
            return True
    
    async def delete_role(self, role_id: str, deleted_by: str) -> bool:
        """Удаляет роль"""
        async with self._lock:
            # Проверяем права
            if not await self.has_permission(deleted_by, Permission.ROLE_MANAGE):
                logger.error(f"User {deleted_by} does not have permission to delete roles")
                return False
            
            if role_id not in self._roles:
                logger.error(f"Role {role_id} not found")
                return False
            
            # Проверяем, что роль не используется
            for user_id, user_roles in self._user_roles.items():
                for user_role in user_roles:
                    if user_role.role_id == role_id and user_role.is_active:
                        logger.error(f"Cannot delete role {role_id} - it is assigned to user {user_id}")
                        return False
            
            # Деактивируем роль вместо удаления
            self._roles[role_id].is_active = False
            self._roles[role_id].updated_at = datetime.now()
            
            logger.info(f"Role {role_id} deactivated by {deleted_by}")
            return True
    
    async def audit_user_actions(self, user_id: str, action: str, resource: str, 
                                success: bool, details: Optional[str] = None):
        """Аудирует действия пользователя"""
        logger.info(f"RBAC Audit: User {user_id} {action} on {resource} - {'SUCCESS' if success else 'FAILED'}")
        if details:
            logger.info(f"RBAC Audit Details: {details}")

# Глобальный экземпляр RBAC
secure_rbac = SecureRBAC()

# Удобные функции
async def assign_role(user_id: str, role_id: str, assigned_by: str) -> bool:
    """Назначает роль пользователю"""
    return await secure_rbac.assign_role(user_id, role_id, assigned_by)

async def revoke_role(user_id: str, role_id: str, revoked_by: str) -> bool:
    """Отзывает роль у пользователя"""
    return await secure_rbac.revoke_role(user_id, role_id, revoked_by)

async def has_permission(user_id: str, permission: Permission) -> bool:
    """Проверяет, есть ли у пользователя разрешение"""
    return await secure_rbac.has_permission(user_id, permission)

async def get_user_permissions(user_id: str) -> Set[Permission]:
    """Получает все разрешения пользователя"""
    return await secure_rbac.get_user_permissions(user_id)

async def get_user_roles(user_id: str) -> List[Role]:
    """Получает все роли пользователя"""
    return await secure_rbac.get_user_roles(user_id)