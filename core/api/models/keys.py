"""
Pydantic модели для управления API ключами (BYOK модель).
"""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator
from enum import Enum

from .base import BaseResponse, TokenUsageBase


class ApiKeyProvider(str, Enum):
    """Поддерживаемые провайдеры AI."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OPENROUTER = "openrouter"
    AZURE = "azure"


class ApiKeyCreateRequest(BaseModel):
    """Запрос на добавление API ключа."""
    provider: str = Field(..., pattern=r'^(openai|anthropic|openrouter|azure)$', description="Провайдер AI")
    api_key: str = Field(..., min_length=10, max_length=200, description="API ключ")
    model: Optional[str] = Field(None, description="Модель AI (опционально)")


class ApiKeyTestRequest(BaseModel):
    """Запрос на тестирование API ключа."""
    provider: str = Field(..., pattern=r'^(openai|anthropic|openrouter|azure)$')
    api_key: str = Field(..., min_length=10, max_length=200)
    model: Optional[str] = Field(None, description="Модель для тестирования")


class ApiKeyResponse(BaseModel):
    """Ответ с информацией об API ключе."""
    provider: str
    display_key: str  # Первые 8 символов для отображения
    model: Optional[str]
    is_valid: bool
    last_used: Optional[datetime]
    created_at: datetime


class ApiKeyTestResponse(BaseResponse):
    """Ответ на тестирование API ключа."""
    provider: str
    status: str  # "success", "error", "invalid_key"
    message: str
    model: Optional[str] = None


class TokenUsageResponse(BaseResponse):
    """Ответ с использованием токенов."""
    usage: Dict[str, Dict[str, TokenUsageBase]]
    total_tokens: int
    total_requests: int
    period_start: datetime
    period_end: datetime


class ApiKeySettingsUpdateRequest(BaseModel):
    """Запрос на обновление настроек API ключа."""
    model: Optional[str] = Field(None, description="Новая модель")
    settings: Optional[Dict] = Field(default_factory=dict, description="Дополнительные настройки")


class ApiKeyListResponse(BaseResponse):
    """Ответ со списком API ключей."""
    keys: List[ApiKeyResponse]
    total_keys: int
    valid_keys: int
