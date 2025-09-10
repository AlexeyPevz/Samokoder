"""
Authentication service contracts
"""
from typing import Protocol, Optional, Dict, Any
from uuid import UUID

class AuthServiceProtocol(Protocol):
    """Protocol for authentication service implementations"""
    
    async def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with email and password"""
        ...
    
    async def register_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register new user"""
        ...
    
    async def get_user_by_id(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        ...
    
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        ...
    
    async def update_user(self, user_id: UUID, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        ...
    
    async def delete_user(self, user_id: UUID) -> bool:
        """Delete user"""
        ...
    
    async def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token"""
        ...
    
    async def refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refresh JWT token"""
        ...
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke JWT token"""
        ...
    
    async def change_password(self, user_id: UUID, old_password: str, new_password: str) -> bool:
        """Change user password"""
        ...
    
    async def reset_password(self, email: str) -> bool:
        """Reset user password"""
        ...

class PasswordServiceProtocol(Protocol):
    """Protocol for password service implementations"""
    
    def hash_password(self, password: str) -> str:
        """Hash password"""
        ...
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        ...
    
    def generate_reset_token(self, user_id: UUID) -> str:
        """Generate password reset token"""
        ...
    
    def validate_reset_token(self, token: str) -> Optional[UUID]:
        """Validate password reset token"""
        ...

class TokenServiceProtocol(Protocol):
    """Protocol for token service implementations"""
    
    def create_access_token(self, user_id: UUID, expires_delta: Optional[int] = None) -> str:
        """Create access token"""
        ...
    
    def create_refresh_token(self, user_id: UUID) -> str:
        """Create refresh token"""
        ...
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate token"""
        ...
    
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode token payload"""
        ...
    
    def revoke_token(self, token: str) -> bool:
        """Revoke token"""
        ...