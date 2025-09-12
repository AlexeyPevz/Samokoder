"""
Адаптер для сервисов безопасности
Уменьшает связность между компонентами
"""

import logging
from typing import Dict, Any, List, Optional
from backend.interfaces.security import IRBACService, IMFAService

logger = logging.getLogger(__name__)

class SecurityAdapter:
    """Адаптер для сервисов безопасности"""
    
    def __init__(self, rbac_service: IRBACService, mfa_service: IMFAService):
        self.rbac_service = rbac_service
        self.mfa_service = mfa_service
    
    # RBAC методы
    def get_user_permissions(self, user_id: str) -> List[str]:
        """Получить разрешения пользователя"""
        user_roles = self.rbac_service.get_user_roles(user_id)
        permissions = set()
        
        for role in user_roles:
            role_permissions = role.get("permissions", [])
            permissions.update(role_permissions)
        
        return list(permissions)
    
    def can_user_access(self, user_id: str, resource: str, action: str) -> bool:
        """Проверить доступ пользователя к ресурсу"""
        permission = f"{resource}:{action}"
        return self.rbac_service.check_permission(user_id, permission)
    
    def assign_role_to_user(self, user_id: str, role_name: str) -> bool:
        """Назначить роль пользователю"""
        # Находим роль по имени
        roles = self.rbac_service.get_all_roles()
        role = next((r for r in roles if r["name"] == role_name), None)
        
        if not role:
            logger.warning(f"Role {role_name} not found")
            return False
        
        return self.rbac_service.assign_role_to_user(user_id, role["id"])
    
    def remove_role_from_user(self, user_id: str, role_name: str) -> bool:
        """Удалить роль у пользователя"""
        # Находим роль по имени
        roles = self.rbac_service.get_all_roles()
        role = next((r for r in roles if r["name"] == role_name), None)
        
        if not role:
            logger.warning(f"Role {role_name} not found")
            return False
        
        return self.rbac_service.remove_role_from_user(user_id, role["id"])
    
    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Получить роли пользователя"""
        return self.rbac_service.get_user_roles(user_id)
    
    def create_user_role(self, name: str, description: str, permissions: List[str]) -> Dict[str, Any]:
        """Создать роль для пользователя"""
        return self.rbac_service.create_role(name, description, permissions)
    
    # MFA методы
    def setup_mfa_for_user(self, user_id: str) -> Dict[str, Any]:
        """Настроить MFA для пользователя"""
        secret = self.mfa_service.generate_secret(user_id)
        qr_code = self.mfa_service.generate_qr_code(user_id, secret)
        backup_codes = self.mfa_service.generate_backup_codes(user_id)
        
        return {
            "secret": secret,
            "qr_code": qr_code,
            "backup_codes": backup_codes
        }
    
    def verify_mfa_token(self, user_id: str, token: str) -> bool:
        """Проверить MFA токен"""
        return self.mfa_service.verify_totp(user_id, token)
    
    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Проверить резервный код"""
        return self.mfa_service.verify_backup_code(user_id, code)
    
    def is_mfa_enabled(self, user_id: str) -> bool:
        """Проверить, включен ли MFA"""
        return self.mfa_service.is_mfa_enabled(user_id)
    
    def disable_mfa_for_user(self, user_id: str) -> bool:
        """Отключить MFA для пользователя"""
        return self.mfa_service.disable_mfa(user_id)
    
    # Комбинированные методы безопасности
    def check_user_access_with_mfa(self, user_id: str, resource: str, action: str, 
                                 mfa_token: Optional[str] = None) -> Dict[str, Any]:
        """Проверить доступ пользователя с учетом MFA"""
        # Проверяем базовые разрешения
        has_permission = self.can_user_access(user_id, resource, action)
        
        if not has_permission:
            return {
                "access_granted": False,
                "reason": "insufficient_permissions"
            }
        
        # Проверяем MFA если включен
        if self.is_mfa_enabled(user_id):
            if not mfa_token:
                return {
                    "access_granted": False,
                    "reason": "mfa_required",
                    "mfa_enabled": True
                }
            
            if not self.verify_mfa_token(user_id, mfa_token):
                return {
                    "access_granted": False,
                    "reason": "invalid_mfa_token",
                    "mfa_enabled": True
                }
        
        return {
            "access_granted": True,
            "mfa_enabled": self.is_mfa_enabled(user_id)
        }
    
    def get_user_security_status(self, user_id: str) -> Dict[str, Any]:
        """Получить статус безопасности пользователя"""
        return {
            "user_id": user_id,
            "roles": self.get_user_roles(user_id),
            "permissions": self.get_user_permissions(user_id),
            "mfa_enabled": self.is_mfa_enabled(user_id),
            "security_level": "high" if self.is_mfa_enabled(user_id) else "medium"
        }