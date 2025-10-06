"""
RBAC Service contracts
"""
from typing import Protocol, List, Dict, Any, Optional
from uuid import UUID

class RBACServiceProtocol(Protocol):
    """Protocol for RBAC service implementations"""
    
    async def check_permission(
        self,
        user_id: UUID,
        resource: str,
        action: str
    ) -> bool:
        """Check if user has permission for action on resource"""
        ...
    
    async def assign_role(
        self,
        user_id: UUID,
        role: str
    ) -> bool:
        """Assign role to user"""
        ...
    
    async def revoke_role(
        self,
        user_id: UUID,
        role: str
    ) -> bool:
        """Revoke role from user"""
        ...
    
    async def get_user_roles(
        self,
        user_id: UUID
    ) -> List[str]:
        """Get all roles for user"""
        ...
    
    async def get_user_permissions(
        self,
        user_id: UUID
    ) -> List[Dict[str, str]]:
        """Get all permissions for user"""
        ...
    
    async def create_role(
        self,
        role_name: str,
        permissions: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Create new role with permissions"""
        ...
    
    async def update_role(
        self,
        role_name: str,
        permissions: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Update role permissions"""
        ...
    
    async def delete_role(
        self,
        role_name: str
    ) -> bool:
        """Delete role"""
        ...
