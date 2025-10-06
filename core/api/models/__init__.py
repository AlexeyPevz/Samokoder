"""
API модели для валидации входных данных.

Этот пакет содержит Pydantic модели для всех API эндпоинтов,
обеспечивая:
- Валидацию данных
- Типизацию
- Документирование
- Защиту от уязвимостей
"""

from .base import (
    BaseResponse,
    ErrorResponse,
    ProjectBase,
    ProjectCreate,
    ProjectResponse,
    UserBase,
    UserCreate,
    UserResponse,
    ApiKeyBase,
    ApiKeyCreate,
    ApiKeyResponse,
    TokenUsageBase,
    PaginationParams,
    PaginatedResponse,
)

from .projects import (
    ProjectCreateRequest,
    ProjectUpdateRequest,
    ProjectListResponse,
    ProjectDetailResponse,
)

from .auth import (
    LoginRequest,
    RegisterRequest,
    AuthResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
)

from .keys import (
    ApiKeyProvider,
    ApiKeyCreateRequest,
    ApiKeyTestRequest,
    ApiKeyResponse,
    ApiKeyTestResponse,
    TokenUsageResponse,
    ApiKeySettingsUpdateRequest,
    ApiKeyListResponse,
)

__all__ = [
    # Base models
    "BaseResponse",
    "ErrorResponse",
    "ProjectBase",
    "ProjectCreate",
    "ProjectResponse",
    "UserBase",
    "UserCreate",
    "UserResponse",
    "ApiKeyBase",
    "ApiKeyCreate",
    "ApiKeyResponse",
    "TokenUsageBase",
    "PaginationParams",
    "PaginatedResponse",
    
    # Project models
    "ProjectCreateRequest",
    "ProjectUpdateRequest",
    "ProjectListResponse",
    "ProjectDetailResponse",
    
    # Auth models
    "LoginRequest",
    "RegisterRequest",
    "AuthResponse",
    "TokenRefreshRequest",
    "TokenRefreshResponse",
    
    # Keys models
    "ApiKeyProvider",
    "ApiKeyCreateRequest",
    "ApiKeyTestRequest",
    "ApiKeyResponse",
    "ApiKeyTestResponse",
    "TokenUsageResponse",
    "ApiKeySettingsUpdateRequest",
    "ApiKeyListResponse",
]
