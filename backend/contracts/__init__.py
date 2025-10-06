"""
Контракты для модулей системы
"""

from .database import (
    DatabaseServiceProtocol,
    UserRepositoryProtocol,
    ProjectRepositoryProtocol,
    ChatRepositoryProtocol
)
from .ai_service import AIServiceProtocol, AIProviderProtocol
from .auth import AuthServiceProtocol, PasswordServiceProtocol, TokenServiceProtocol
from .file_service import FileServiceProtocol, FileRepositoryProtocol
from .supabase_service import SupabaseServiceProtocol
from .rbac import RBACServiceProtocol
from .mfa import MFAServiceProtocol

__all__ = [
    # Database contracts
    "DatabaseServiceProtocol",
    "UserRepositoryProtocol", 
    "ProjectRepositoryProtocol",
    "ChatRepositoryProtocol",
    # AI contracts
    "AIServiceProtocol",
    "AIProviderProtocol",
    # Auth contracts
    "AuthServiceProtocol",
    "PasswordServiceProtocol", 
    "TokenServiceProtocol",
    # File contracts
    "FileServiceProtocol",
    "FileRepositoryProtocol",
    # Supabase contracts
    "SupabaseServiceProtocol",
    # RBAC contracts
    "RBACServiceProtocol",
    # MFA contracts
    "MFAServiceProtocol"
]