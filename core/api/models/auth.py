"""
Pydantic модели для аутентификации API.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, validator

from .base import BaseResponse


class LoginRequest(BaseModel):
    """Запрос на вход в систему."""
    email: str = Field(..., pattern=r'^[^@]+@[^@]+\.[^@]+$', description="Email адрес")
    password: str = Field(..., min_length=1, description="Пароль")
    
    @validator('email')
    def validate_email(cls, v):
        """Валидация email."""
        if len(v) > 254:  # RFC 5321 limit
            raise ValueError('Email слишком длинный')
        return v.lower().strip()


class RegisterRequest(BaseModel):
    """Запрос на регистрацию."""
    email: str = Field(..., pattern=r'^[^@]+@[^@]+\.[^@]+$', description="Email адрес")
    password: str = Field(..., min_length=6, max_length=128, description="Пароль")
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Валидация сложности пароля."""
        if len(v) < 6:
            raise ValueError('Пароль должен содержать минимум 6 символов')
        return v
    
    @validator('email')
    def validate_email(cls, v):
        """Валидация email."""
        if len(v) > 254:
            raise ValueError('Email слишком длинный')
        return v.lower().strip()


class AuthResponse(BaseResponse):
    """Ответ аутентификации."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int  # seconds
    user_id: int
    email: str


class TokenRefreshRequest(BaseModel):
    """Запрос на обновление токена."""
    refresh_token: str = Field(..., description="Refresh токен")


class TokenRefreshResponse(BaseResponse):
    """Ответ с обновленным токеном."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
