"""
API Layer Dependency Providers
Provides services to API endpoints through DI container
"""
from backend.contracts.ai_service import AIServiceProtocol
from backend.contracts.rbac import RBACServiceProtocol
from backend.contracts.mfa import MFAServiceProtocol
from backend.core.dependency_injection import get_container


def provide_ai_service() -> AIServiceProtocol:
    """Provide AI service from DI container"""
    return get_container().get(AIServiceProtocol)


def provide_rbac_service() -> RBACServiceProtocol:
    """Provide RBAC service from DI container"""
    return get_container().get(RBACServiceProtocol)


def provide_mfa_service() -> MFAServiceProtocol:
    """Provide MFA service from DI container"""
    return get_container().get(MFAServiceProtocol)
