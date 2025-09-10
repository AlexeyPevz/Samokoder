"""
Pydantic модели для валидации входящих запросов
Обеспечивают безопасность и типизацию API
"""

from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class ProjectStatus(str, Enum):
    """Статусы проекта"""
    DRAFT = "draft"
    GENERATING = "generating"
    COMPLETED = "completed"
    ERROR = "error"
    ARCHIVED = "archived"

class SubscriptionTier(str, Enum):
    """Тарифные планы"""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"

class AIProvider(str, Enum):
    """AI провайдеры"""
    OPENROUTER = "openrouter"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"

# === АУТЕНТИФИКАЦИЯ ===

class LoginRequest(BaseModel):
    """Запрос на вход"""
    email: EmailStr = Field(..., description="Email пользователя")
    password: str = Field(..., min_length=8, max_length=128, description="Пароль")
    
    @validator('password')
    def validate_password(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        if not any(c.islower() for c in v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        if not any(c.isdigit() for c in v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        return v

class RegisterRequest(BaseModel):
    """Запрос на регистрацию"""
    email: EmailStr = Field(..., description="Email пользователя")
    password: str = Field(..., min_length=8, max_length=128, description="Пароль")
    full_name: Optional[str] = Field(None, max_length=100, description="Полное имя")
    
    @validator('password')
    def validate_password(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        if not any(c.islower() for c in v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        if not any(c.isdigit() for c in v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        return v

# === ПРОЕКТЫ ===

class ProjectCreateRequest(BaseModel):
    """Запрос на создание проекта"""
    name: str = Field(..., min_length=1, max_length=100, description="Название проекта")
    description: str = Field(..., min_length=10, max_length=1000, description="Описание проекта")
    tech_stack: Optional[Dict[str, Any]] = Field(None, description="Технологический стек")
    ai_config: Optional[Dict[str, Any]] = Field(None, description="Конфигурация AI")
    
    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Название проекта не может быть пустым')
        return v.strip()
    
    @validator('description')
    def validate_description(cls, v):
        if not v.strip():
            raise ValueError('Описание проекта не может быть пустым')
        return v.strip()

class ProjectUpdateRequest(BaseModel):
    """Запрос на обновление проекта"""
    name: Optional[str] = Field(None, min_length=1, max_length=100, description="Название проекта")
    description: Optional[str] = Field(None, min_length=10, max_length=1000, description="Описание проекта")
    tech_stack: Optional[Dict[str, Any]] = Field(None, description="Технологический стек")
    ai_config: Optional[Dict[str, Any]] = Field(None, description="Конфигурация AI")
    status: Optional[ProjectStatus] = Field(None, description="Статус проекта")

class ProjectListRequest(BaseModel):
    """Запрос на получение списка проектов"""
    page: int = Field(1, ge=1, description="Номер страницы")
    limit: int = Field(10, ge=1, le=100, description="Количество проектов на странице")
    status: Optional[ProjectStatus] = Field(None, description="Фильтр по статусу")
    search: Optional[str] = Field(None, max_length=100, description="Поисковый запрос")

# === ЧАТ И AI ===

class ChatRequest(BaseModel):
    """Запрос на чат с AI"""
    message: str = Field(..., min_length=1, max_length=4000, description="Сообщение пользователя")
    context: str = Field("chat", max_length=50, description="Контекст чата")
    model: Optional[str] = Field(None, max_length=100, description="Модель AI")
    provider: Optional[AIProvider] = Field(None, description="Провайдер AI")
    max_tokens: int = Field(4096, ge=1, le=32000, description="Максимальное количество токенов")
    temperature: float = Field(0.7, ge=0.0, le=2.0, description="Температура генерации")
    
    @validator('message')
    def validate_message(cls, v):
        if not v.strip():
            raise ValueError('Сообщение не может быть пустым')
        return v.strip()

class AIUsageRequest(BaseModel):
    """Запрос на получение статистики использования AI"""
    start_date: Optional[datetime] = Field(None, description="Начальная дата")
    end_date: Optional[datetime] = Field(None, description="Конечная дата")
    provider: Optional[AIProvider] = Field(None, description="Фильтр по провайдеру")

# === API КЛЮЧИ ===

class APIKeyCreateRequest(BaseModel):
    """Запрос на создание API ключа"""
    provider: AIProvider = Field(..., description="Провайдер AI")
    key_name: str = Field(..., min_length=1, max_length=50, description="Название ключа")
    api_key: str = Field(..., min_length=10, max_length=200, description="API ключ")
    
    @validator('key_name')
    def validate_key_name(cls, v):
        if not v.strip():
            raise ValueError('Название ключа не может быть пустым')
        return v.strip()
    
    @validator('api_key')
    def validate_api_key(cls, v, values):
        provider = values.get('provider')
        if provider == AIProvider.OPENAI and not v.startswith('sk-'):
            raise ValueError('OpenAI ключ должен начинаться с "sk-"')
        if provider == AIProvider.ANTHROPIC and not v.startswith('sk-ant-'):
            raise ValueError('Anthropic ключ должен начинаться с "sk-ant-"')
        if provider == AIProvider.OPENROUTER and not v.startswith('sk-or-'):
            raise ValueError('OpenRouter ключ должен начинаться с "sk-or-"')
        return v

class APIKeyUpdateRequest(BaseModel):
    """Запрос на обновление API ключа"""
    key_name: Optional[str] = Field(None, min_length=1, max_length=50, description="Название ключа")
    is_active: Optional[bool] = Field(None, description="Активность ключа")

# === НАСТРОЙКИ ПОЛЬЗОВАТЕЛЯ ===

class UserSettingsUpdateRequest(BaseModel):
    """Запрос на обновление настроек пользователя"""
    default_model: Optional[str] = Field(None, max_length=100, description="Модель по умолчанию")
    default_provider: Optional[AIProvider] = Field(None, description="Провайдер по умолчанию")
    auto_export: Optional[bool] = Field(None, description="Автоматический экспорт")
    notifications_email: Optional[bool] = Field(None, description="Email уведомления")
    notifications_generation: Optional[bool] = Field(None, description="Уведомления о генерации")
    theme: Optional[str] = Field(None, pattern="^(light|dark|auto)$", description="Тема интерфейса")

# === ФАЙЛЫ ===

class FileUploadRequest(BaseModel):
    """Запрос на загрузку файла"""
    filename: str = Field(..., min_length=1, max_length=255, description="Имя файла")
    content_type: str = Field(..., max_length=100, description="Тип содержимого")
    size: int = Field(..., ge=1, le=52428800, description="Размер файла в байтах")
    
    @validator('filename')
    def validate_filename(cls, v):
        # Проверяем на path traversal атаки
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Недопустимое имя файла')
        return v

class FileContentRequest(BaseModel):
    """Запрос на получение содержимого файла"""
    file_path: str = Field(..., min_length=1, max_length=500, description="Путь к файлу")
    
    @validator('file_path')
    def validate_file_path(cls, v):
        # Проверяем на path traversal атаки
        if '..' in v or v.startswith('/') or '\\' in v:
            raise ValueError('Недопустимый путь к файлу')
        return v

# === ЭКСПОРТ ===

class ExportRequest(BaseModel):
    """Запрос на экспорт проекта"""
    format: str = Field("zip", pattern="^(zip|tar|tar\.gz)$", description="Формат экспорта")
    include_dependencies: bool = Field(True, description="Включить зависимости")
    include_documentation: bool = Field(True, description="Включить документацию")

# === ПОИСК И ФИЛЬТРАЦИЯ ===

class SearchRequest(BaseModel):
    """Запрос на поиск"""
    query: str = Field(..., min_length=1, max_length=100, description="Поисковый запрос")
    page: int = Field(1, ge=1, description="Номер страницы")
    limit: int = Field(10, ge=1, le=100, description="Количество результатов")
    
    @validator('query')
    def validate_query(cls, v):
        if not v.strip():
            raise ValueError('Поисковый запрос не может быть пустым')
        return v.strip()

# === ВАЛИДАЦИЯ КЛЮЧЕЙ ===

class APIKeyValidationRequest(BaseModel):
    """Запрос на валидацию API ключей"""
    keys: Dict[AIProvider, str] = Field(..., description="Словарь ключей для валидации")
    
    @validator('keys')
    def validate_keys_dict(cls, v):
        if not v:
            raise ValueError('Словарь ключей не может быть пустым')
        for provider, key in v.items():
            if not key or len(key) < 10:
                raise ValueError(f'Ключ для {provider} слишком короткий')
        return v