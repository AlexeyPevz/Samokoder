"""
Интерфейсы для безопасности
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class IRBACService(ABC):
    """Интерфейс RBAC сервиса"""
    
    @abstractmethod
    def get_all_roles(self) -> List[Dict[str, Any]]:
        """Получить все роли"""
        pass
    
    @abstractmethod
    def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        """Получить роль по ID"""
        pass
    
    @abstractmethod
    def create_role(self, name: str, description: str, permissions: List[str]) -> Dict[str, Any]:
        """Создать роль"""
        pass
    
    @abstractmethod
    def update_role(self, role_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Обновить роль"""
        pass
    
    @abstractmethod
    def delete_role(self, role_id: str) -> bool:
        """Удалить роль"""
        pass
    
    @abstractmethod
    def assign_role_to_user(self, user_id: str, role_id: str) -> bool:
        """Назначить роль пользователю"""
        pass
    
    @abstractmethod
    def remove_role_from_user(self, user_id: str, role_id: str) -> bool:
        """Удалить роль у пользователя"""
        pass
    
    @abstractmethod
    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Получить роли пользователя"""
        pass
    
    @abstractmethod
    def check_permission(self, user_id: str, permission: str) -> bool:
        """Проверить разрешение"""
        pass

class IMFAService(ABC):
    """Интерфейс MFA сервиса"""
    
    @abstractmethod
    def generate_secret(self, user_id: str) -> str:
        """Сгенерировать секрет для пользователя"""
        pass
    
    @abstractmethod
    def generate_qr_code(self, user_id: str, secret: str) -> str:
        """Сгенерировать QR код"""
        pass
    
    @abstractmethod
    def generate_backup_codes(self, user_id: str, count: int = 10) -> List[str]:
        """Сгенерировать резервные коды"""
        pass
    
    @abstractmethod
    def verify_totp(self, user_id: str, token: str) -> bool:
        """Проверить TOTP токен"""
        pass
    
    @abstractmethod
    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Проверить резервный код"""
        pass
    
    @abstractmethod
    def is_mfa_enabled(self, user_id: str) -> bool:
        """Проверить, включен ли MFA"""
        pass
    
    @abstractmethod
    def disable_mfa(self, user_id: str) -> bool:
        """Отключить MFA"""
        pass