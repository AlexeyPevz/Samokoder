"""
Pydantic модели для валидации входящих запросов
Обеспечивают безопасность и типизацию API
"""

from pydantic import BaseModel, Field, field_validator, EmailStr
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
    
    model_config = {
        "error_messages": {
            "value_error.string_too_short": "не может быть пустым",
            "value_error.string_too_long": "слишком длинный",
            "value_error.email": "неверный формат email"
        }
    }
    
    @field_validator('password')
    @classmethod
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
    
    @field_validator('password')
    @classmethod
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
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Название проекта не может быть пустым')
        return v.strip()
    
    @field_validator('description')
    @classmethod
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
    message: str = Field(..., description="Сообщение пользователя")
    context: str = Field("chat", max_length=50, description="Контекст чата")
    model: Optional[str] = Field(None, max_length=100, description="Модель AI")
    provider: Optional[AIProvider] = Field(None, description="Провайдер AI")
    max_tokens: int = Field(4096, ge=1, le=32000, description="Максимальное количество токенов")
    temperature: float = Field(0.7, description="Температура генерации")
    
    @field_validator('message')
    @classmethod
    def validate_message(cls, v):
        if not v or not v.strip():
            raise ValueError('Сообщение не может быть пустым')
        if len(v) > 4000:
            raise ValueError('Сообщение слишком длинное')
        return v.strip()
    
    @field_validator('max_tokens')
    @classmethod
    def validate_max_tokens(cls, v):
        if v < 1:
            raise ValueError('Максимальное количество токенов должно быть больше 0')
        if v > 32000:
            raise ValueError('Максимальное количество токенов должно быть меньше или равно 32000')
        return v
    
    @field_validator('temperature')
    @classmethod
    def validate_temperature(cls, v):
        if v < 0.0:
            raise ValueError('Температура должна быть больше или равна 0.0')
        if v > 2.0:
            raise ValueError('Температура должна быть меньше или равна 2.0')
        return v

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
    
    @field_validator('key_name')
    @classmethod
    def validate_key_name(cls, v):
        if not v.strip():
            raise ValueError('Название ключа не может быть пустым')
        return v.strip()
    
    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v, info):
        provider = info.data.get('provider')
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
    theme: Optional[str] = Field(None, description="Тема интерфейса")
    
    @field_validator('theme')
    @classmethod
    def validate_theme(cls, v):
        if v is not None and v not in ['light', 'dark', 'auto']:
            raise ValueError('Тема должна быть light, dark или auto')
        return v

# === ФАЙЛЫ ===

class FileUploadRequest(BaseModel):
    """Запрос на загрузку файла"""
    filename: str = Field(..., min_length=1, max_length=255, description="Имя файла")
    content_type: str = Field(..., max_length=100, description="Тип содержимого")
    size: int = Field(..., ge=1, le=52428800, description="Размер файла в байтах")
    
    @field_validator('filename')
    @classmethod
    def validate_filename(cls, v):
        # Проверяем на path traversal атаки
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Недопустимое имя файла')
        return v

class FileContentRequest(BaseModel):
    """Запрос на получение содержимого файла"""
    file_path: str = Field(..., min_length=1, max_length=500, description="Путь к файлу")
    
    @field_validator('file_path')
    @classmethod
    def validate_file_path(cls, v):
        # Проверяем на path traversal атаки
        if '..' in v or v.startswith('/') or '\\' in v:
            raise ValueError('Недопустимый путь к файлу')
        return v

# === ЭКСПОРТ ===

class ExportRequest(BaseModel):
    """Запрос на экспорт проекта"""
    format: str = Field("zip", pattern=r"^(zip|tar|tar\.gz)$", description="Формат экспорта")
    include_dependencies: bool = Field(True, description="Включить зависимости")
    include_documentation: bool = Field(True, description="Включить документацию")

# === MFA ===

class MFASetupRequest(BaseModel):
    """Запрос на настройку MFA"""
    pass  # Настройка не требует дополнительных данных

class MFAVerifyRequest(BaseModel):
    """Запрос на проверку MFA кода"""
    code: str = Field(..., min_length=6, max_length=6, description="6-значный TOTP код")
    
    @field_validator('code')
    @classmethod
    def validate_code(cls, v: str) -> str:
        if not v.isdigit() or len(v) != 6:
            raise ValueError('Код должен содержать 6 цифр')
        return v

# === RBAC ===

class RoleCreateRequest(BaseModel):
    """Запрос на создание роли"""
    name: str = Field(..., min_length=1, max_length=100, description="Название роли")
    description: str = Field(..., max_length=500, description="Описание роли")
    permissions: List[str] = Field(..., description="Список разрешений")

class PermissionAssignRequest(BaseModel):
    """Запрос на назначение разрешения"""
    permission: str = Field(..., min_length=1, max_length=100, description="Разрешение")

# === ПОИСК И ФИЛЬТРАЦИЯ ===

class SearchRequest(BaseModel):
    """Запрос на поиск"""
    query: str = Field(..., min_length=1, max_length=100, description="Поисковый запрос")
    page: int = Field(1, ge=1, description="Номер страницы")
    limit: int = Field(10, ge=1, le=100, description="Количество результатов")
    
    @field_validator('query')
    @classmethod
    def validate_query(cls, v):
        if not v.strip():
            raise ValueError('Поисковый запрос не может быть пустым')
        return v.strip()

# === ВАЛИДАЦИЯ КЛЮЧЕЙ ===

class APIKeyValidationRequest(BaseModel):
    """Запрос на валидацию API ключей"""
    keys: Dict[AIProvider, str] = Field(..., description="Словарь ключей для валидации")
    
    @field_validator('keys')
    @classmethod
    def validate_keys_dict(cls, v):
        if not v:
            raise ValueError('Словарь ключей не может быть пустым')
        for provider, key in v.items():
            if not key or len(key) < 10:
                raise ValueError(f'Ключ для {provider} слишком короткий')
        return v