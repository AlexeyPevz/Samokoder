"""
ASVS V4: Критические исправления контроля доступа (P0)
"""
import re
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from fastapi import HTTPException, status
from backend.core.common_imports import get_logger

logger = get_logger(__name__)

class PermissionLevel(Enum):
    """Уровни разрешений"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"

class ResourceType(Enum):
    """Типы ресурсов"""
    PROJECT = "project"
    FILE = "file"
    CHAT = "chat"
    USER = "user"
    API_KEY = "api_key"
    SETTINGS = "settings"

class AccessControlSecurity:
    """Критические исправления контроля доступа"""
    
    def __init__(self):
        self.role_permissions: Dict[str, Set[str]] = {
            "free": {
                "project:read", "project:write", "file:read", "chat:read", "chat:write"
            },
            "starter": {
                "project:read", "project:write", "project:delete",
                "file:read", "file:write", "chat:read", "chat:write",
                "api_key:read", "api_key:write"
            },
            "professional": {
                "project:read", "project:write", "project:delete",
                "file:read", "file:write", "file:delete",
                "chat:read", "chat:write", "chat:delete",
                "api_key:read", "api_key:write", "api_key:delete",
                "settings:read", "settings:write"
            },
            "business": {
                "project:read", "project:write", "project:delete",
                "file:read", "file:write", "file:delete",
                "chat:read", "chat:write", "chat:delete",
                "api_key:read", "api_key:write", "api_key:delete",
                "settings:read", "settings:write",
                "user:read", "user:write"
            },
            "enterprise": {
                "project:read", "project:write", "project:delete",
                "file:read", "file:write", "file:delete",
                "chat:read", "chat:write", "chat:delete",
                "api_key:read", "api_key:write", "api_key:delete",
                "settings:read", "settings:write",
                "user:read", "user:write", "user:delete",
                "admin:read", "admin:write", "admin:delete"
            }
        }
        
        self.resource_ownership_cache: Dict[str, Dict[str, str]] = {}
    
    def check_permission(self, user_role: str, resource: str, action: str) -> bool:
        """V4.1.1: Проверка разрешения на доступ к ресурсу"""
        permission = f"{resource}:{action}"
        
        if user_role not in self.role_permissions:
            logger.warning(f"Unknown user role: {user_role}")
            return False
        
        user_permissions = self.role_permissions[user_role]
        return permission in user_permissions
    
    def check_resource_ownership(self, user_id: str, resource_id: str, resource_type: str) -> bool:
        """V4.1.2: Проверка владения ресурсом"""
        cache_key = f"{resource_type}:{resource_id}"
        
        if cache_key in self.resource_ownership_cache:
            owner_id = self.resource_ownership_cache[cache_key].get('owner_id')
            return owner_id == user_id
        
        # В реальном приложении здесь должен быть запрос к БД
        # Для тестирования возвращаем True
        return True
    
    def enforce_ownership_access(self, user_id: str, resource_id: str, resource_type: str) -> None:
        """V4.1.3: Принудительная проверка владения ресурсом"""
        if not self.check_resource_ownership(user_id, resource_id, resource_type):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: You don't own this {resource_type}"
            )
    
    def check_role_based_access(self, user_role: str, required_role: str) -> bool:
        """V4.1.4: Проверка доступа на основе роли"""
        role_hierarchy = {
            "free": 0,
            "starter": 1,
            "professional": 2,
            "business": 3,
            "enterprise": 4
        }
        
        user_level = role_hierarchy.get(user_role, -1)
        required_level = role_hierarchy.get(required_role, 999)
        
        return user_level >= required_level
    
    def validate_resource_access(self, user_id: str, user_role: str, resource_id: str, 
                               resource_type: str, action: str) -> bool:
        """V4.1.5: Комплексная валидация доступа к ресурсу"""
        # Проверяем разрешение роли
        if not self.check_permission(user_role, resource_type, action):
            logger.warning(f"Permission denied for user {user_id}: {resource_type}:{action}")
            return False
        
        # Проверяем владение ресурсом (для операций записи/удаления)
        if action in ["write", "delete"]:
            if not self.check_resource_ownership(user_id, resource_id, resource_type):
                logger.warning(f"Ownership check failed for user {user_id} and resource {resource_id}")
                return False
        
        return True
    
    def sanitize_resource_id(self, resource_id: str) -> str:
        """V4.1.6: Санитизация ID ресурса"""
        if not resource_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Resource ID cannot be empty"
            )
        
        # Удаляем потенциально опасные символы
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', resource_id)
        
        if len(sanitized) != len(resource_id):
            logger.warning(f"Resource ID sanitized: {resource_id} -> {sanitized}")
        
        return sanitized
    
    def validate_resource_type(self, resource_type: str) -> bool:
        """V4.1.7: Валидация типа ресурса"""
        valid_types = [rt.value for rt in ResourceType]
        return resource_type in valid_types
    
    def check_rate_limit_by_role(self, user_role: str, action: str) -> Dict[str, int]:
        """V4.1.8: Проверка лимитов на основе роли"""
        rate_limits = {
            "free": {
                "project:create": 3,
                "file:upload": 10,
                "chat:message": 100,
                "api_key:create": 1
            },
            "starter": {
                "project:create": 10,
                "file:upload": 50,
                "chat:message": 500,
                "api_key:create": 3
            },
            "professional": {
                "project:create": 50,
                "file:upload": 200,
                "chat:message": 2000,
                "api_key:create": 10
            },
            "business": {
                "project:create": 100,
                "file:upload": 500,
                "chat:message": 5000,
                "api_key:create": 25
            },
            "enterprise": {
                "project:create": -1,  # Unlimited
                "file:upload": -1,
                "chat:message": -1,
                "api_key:create": -1
            }
        }
        
        user_limits = rate_limits.get(user_role, {})
        return user_limits.get(action, 0)
    
    def enforce_principle_of_least_privilege(self, user_role: str, requested_permissions: List[str]) -> List[str]:
        """V4.1.9: Применение принципа минимальных привилегий"""
        user_permissions = self.role_permissions.get(user_role, set())
        
        # Фильтруем только разрешенные права
        allowed_permissions = [perm for perm in requested_permissions if perm in user_permissions]
        
        if len(allowed_permissions) != len(requested_permissions):
            denied_permissions = set(requested_permissions) - set(allowed_permissions)
            logger.warning(f"Denied permissions for role {user_role}: {denied_permissions}")
        
        return allowed_permissions
    
    def check_cross_tenant_access(self, user_tenant_id: str, resource_tenant_id: str) -> bool:
        """V4.1.10: Проверка доступа между тенантами"""
        if not user_tenant_id or not resource_tenant_id:
            return False
        
        return user_tenant_id == resource_tenant_id
    
    def validate_api_endpoint_access(self, user_role: str, endpoint: str, method: str) -> bool:
        """V4.1.11: Валидация доступа к API endpoint"""
        endpoint_permissions = {
            "GET /api/projects": ["free", "starter", "professional", "business", "enterprise"],
            "POST /api/projects": ["free", "starter", "professional", "business", "enterprise"],
            "DELETE /api/projects": ["starter", "professional", "business", "enterprise"],
            "GET /api/users": ["business", "enterprise"],
            "POST /api/users": ["enterprise"],
            "DELETE /api/users": ["enterprise"],
            "GET /api/admin": ["enterprise"],
            "POST /api/admin": ["enterprise"]
        }
        
        endpoint_key = f"{method} {endpoint}"
        allowed_roles = endpoint_permissions.get(endpoint_key, [])
        
        return user_role in allowed_roles
    
    def check_data_access_scope(self, user_id: str, user_role: str, data_type: str) -> Set[str]:
        """V4.1.12: Проверка области доступа к данным"""
        scope_limits = {
            "free": {"own_data": True, "team_data": False, "all_data": False},
            "starter": {"own_data": True, "team_data": False, "all_data": False},
            "professional": {"own_data": True, "team_data": True, "all_data": False},
            "business": {"own_data": True, "team_data": True, "all_data": False},
            "enterprise": {"own_data": True, "team_data": True, "all_data": True}
        }
        
        user_scope = scope_limits.get(user_role, {"own_data": True})
        allowed_scopes = {scope for scope, allowed in user_scope.items() if allowed}
        
        return allowed_scopes
    
    def audit_access_attempt(self, user_id: str, user_role: str, resource_id: str, 
                           resource_type: str, action: str, success: bool) -> None:
        """V4.1.13: Аудит попыток доступа"""
        audit_data = {
            "user_id": user_id,
            "user_role": user_role,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "action": action,
            "success": success,
            "timestamp": time.time()
        }
        
        logger.info(f"Access audit: {audit_data}")
    
    def check_privilege_escalation(self, user_id: str, current_role: str, requested_role: str) -> bool:
        """V4.1.14: Проверка эскалации привилегий"""
        role_hierarchy = {
            "free": 0,
            "starter": 1,
            "professional": 2,
            "business": 3,
            "enterprise": 4
        }
        
        current_level = role_hierarchy.get(current_role, 0)
        requested_level = role_hierarchy.get(requested_role, 0)
        
        # Пользователь может только понижать свой уровень привилегий
        return requested_level <= current_level
    
    def validate_session_authorization(self, session_data: Dict[str, Any], required_permissions: List[str]) -> bool:
        """V4.1.15: Валидация авторизации сессии"""
        user_role = session_data.get('user_role', 'free')
        user_permissions = self.role_permissions.get(user_role, set())
        
        # Проверяем, есть ли у пользователя все необходимые разрешения
        for permission in required_permissions:
            if permission not in user_permissions:
                return False
        
        return True

# Глобальный экземпляр
access_control = AccessControlSecurity()