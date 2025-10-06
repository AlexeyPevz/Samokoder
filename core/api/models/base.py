"""
Базовые Pydantic модели для API валидации.

Эти модели обеспечивают:
- Валидацию входных данных
- Типизацию
- Документирование API
- Защиту от SQL injection
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, validator
from uuid import UUID


class BaseResponse(BaseModel):
    """Базовая модель для всех ответов API."""
    
    class Config:
        from_attributes = True  # Позволяет работать с SQLAlchemy моделями


class ErrorResponse(BaseModel):
    """Модель для ошибок API."""
    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Project not found",
                "error_code": "PROJECT_NOT_FOUND",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }


class ProjectBase(BaseModel):
    """Базовая модель проекта."""
    name: str = Field(..., min_length=1, max_length=100, description="Название проекта")
    description: Optional[str] = Field(None, max_length=1000, description="Описание проекта")


class ProjectCreate(ProjectBase):
    """Модель для создания проекта."""
    
    @validator('name')
    def validate_project_name(cls, v):
        """Валидация названия проекта."""
        if not v.strip():
            raise ValueError('Название проекта не может быть пустым')
        
        # Запрещенные символы
        forbidden_chars = ['<', '>', '&', '"', "'", '/', '\\']
        for char in forbidden_chars:
            if char in v:
                raise ValueError(f'Название проекта содержит запрещенный символ: {char}')
        
        return v.strip()


class ProjectResponse(ProjectBase):
    """Модель ответа с проектом."""
    id: UUID
    created_at: datetime
    user_id: int


class UserBase(BaseModel):
    """Базовая модель пользователя."""
    email: str = Field(..., pattern=r'^[^@]+@[^@]+\.[^@]+$', description="Email адрес")


class UserCreate(UserBase):
    """Модель для создания пользователя."""
    password: str = Field(..., min_length=8, max_length=128, description="Пароль")
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Валидация сложности пароля."""
        if len(v) < 8:
            raise ValueError('Пароль должен содержать минимум 8 символов')
        
        # Проверки на различные типы символов
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        
        if not (has_upper and has_lower and has_digit):
            raise ValueError('Пароль должен содержать буквы верхнего и нижнего регистра, а также цифры')
        
        return v


class UserResponse(UserBase):
    """Модель ответа с пользователем."""
    id: int
    tier: str
    created_at: datetime
    projects_count: int = 0


class ApiKeyBase(BaseModel):
    """Базовая модель API ключа."""
    provider: str = Field(..., pattern=r'^(openai|anthropic|openrouter|azure)$', description="Провайдер AI")
    api_key: str = Field(..., min_length=10, max_length=200, description="API ключ")


class ApiKeyCreate(ApiKeyBase):
    """Модель для добавления API ключа."""
    model: Optional[str] = Field(None, description="Модель AI (опционально)")


class ApiKeyResponse(ApiKeyBase):
    """Модель ответа с API ключом."""
    id: int
    display_key: str  # Первые 8 символов ключа для отображения
    is_valid: bool
    created_at: datetime


class TokenUsageBase(BaseModel):
    """Базовая модель использования токенов."""
    provider: str
    model: str
    total_tokens: int
    requests: int


class PaginationParams(BaseModel):
    """Параметры пагинации."""
    page: int = Field(1, ge=1, description="Номер страницы")
    limit: int = Field(10, ge=1, le=100, description="Количество элементов на странице")


class PaginatedResponse(BaseModel):
    """Модель пагинированного ответа."""
    items: List
    total: int
    page: int
    limit: int
    pages: int
