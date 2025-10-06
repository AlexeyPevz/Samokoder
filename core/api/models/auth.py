"""
Pydantic модели для аутентификации API.
"""

from datetime import datetime
from typing import Optional, Set
import re
from pydantic import BaseModel, Field, validator

from .base import BaseResponse

# Common passwords to reject (P1-2)
COMMON_PASSWORDS: Set[str] = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password123", "admin", "letmein", "welcome", "monkey",
    "1234567890", "password1", "123456789", "password!", "Password123"
}


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
    password: str = Field(..., min_length=8, max_length=128, description="Пароль")
    
    @validator('password')
    def validate_password_strength(cls, v):
        """
        Валидация сложности пароля согласно ASVS 2.1.1 (P1-2).
        
        Требования:
        - Минимум 8 символов
        - Заглавная буква
        - Строчная буква
        - Цифра
        - Специальный символ
        - Не должен быть в списке распространенных паролей
        """
        if len(v) < 8:
            raise ValueError('Пароль должен содержать минимум 8 символов')
        
        # Check for uppercase
        if not re.search(r'[A-Z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        
        # Check for lowercase
        if not re.search(r'[a-z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        
        # Check for digit
        if not re.search(r'\d', v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\];\'\\\/`~]', v):
            raise ValueError('Пароль должен содержать хотя бы один специальный символ')
        
        # Check against common passwords
        if v.lower() in COMMON_PASSWORDS:
            raise ValueError('Этот пароль слишком распространенный. Выберите более уникальный пароль.')
        
        # Check for sequential characters (aaa, 111, etc.)
        if re.search(r'(.)\1{2,}', v):
            raise ValueError('Пароль не должен содержать более 2 одинаковых символов подряд')
        
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
