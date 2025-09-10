"""
Pydantic модели для валидации исходящих ответов
Обеспечивают консистентность API и типизацию
"""

from pydantic import BaseModel, Field
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

# === БАЗОВЫЕ ОТВЕТЫ ===

class BaseResponse(BaseModel):
    """Базовый ответ API"""
    success: bool = Field(..., description="Статус выполнения")
    message: str = Field(..., description="Сообщение")
    timestamp: datetime = Field(default_factory=datetime.now, description="Время ответа")

class ErrorResponse(BaseModel):
    """Ответ с ошибкой"""
    success: bool = Field(False, description="Статус выполнения")
    error: str = Field(..., description="Тип ошибки")
    message: str = Field(..., description="Сообщение об ошибке")
    details: Optional[Dict[str, Any]] = Field(None, description="Детали ошибки")
    timestamp: datetime = Field(default_factory=datetime.now, description="Время ошибки")

class PaginatedResponse(BaseModel):
    """Пагинированный ответ"""
    items: List[Any] = Field(..., description="Элементы")
    total: int = Field(..., description="Общее количество")
    page: int = Field(..., description="Текущая страница")
    limit: int = Field(..., description="Количество на странице")
    pages: int = Field(..., description="Общее количество страниц")

# === АУТЕНТИФИКАЦИЯ ===

class UserResponse(BaseModel):
    """Информация о пользователе"""
    id: str = Field(..., description="ID пользователя")
    email: str = Field(..., description="Email")
    full_name: Optional[str] = Field(None, description="Полное имя")
    avatar_url: Optional[str] = Field(None, description="URL аватара")
    subscription_tier: SubscriptionTier = Field(..., description="Тарифный план")
    subscription_status: str = Field(..., description="Статус подписки")
    api_credits_balance: float = Field(..., description="Баланс API кредитов")
    created_at: datetime = Field(..., description="Дата создания")
    updated_at: datetime = Field(..., description="Дата обновления")

class LoginResponse(BaseModel):
    """Ответ на вход"""
    success: bool = Field(True, description="Статус входа")
    message: str = Field(..., description="Сообщение")
    user: UserResponse = Field(..., description="Информация о пользователе")
    access_token: str = Field(..., description="Токен доступа")
    token_type: str = Field("bearer", description="Тип токена")
    expires_in: int = Field(..., description="Время жизни токена в секундах")

# === ПРОЕКТЫ ===

class ProjectResponse(BaseModel):
    """Информация о проекте"""
    id: str = Field(..., description="ID проекта")
    user_id: str = Field(..., description="ID пользователя")
    name: str = Field(..., description="Название проекта")
    description: str = Field(..., description="Описание проекта")
    status: ProjectStatus = Field(..., description="Статус проекта")
    tech_stack: Dict[str, Any] = Field(default_factory=dict, description="Технологический стек")
    ai_config: Dict[str, Any] = Field(default_factory=dict, description="Конфигурация AI")
    file_count: int = Field(0, description="Количество файлов")
    total_size_bytes: int = Field(0, description="Общий размер в байтах")
    generation_time_seconds: int = Field(0, description="Время генерации в секундах")
    generation_progress: int = Field(0, description="Прогресс генерации (0-100)")
    current_agent: Optional[str] = Field(None, description="Текущий агент")
    created_at: datetime = Field(..., description="Дата создания")
    updated_at: datetime = Field(..., description="Дата обновления")
    archived_at: Optional[datetime] = Field(None, description="Дата архивирования")

class ProjectListResponse(BaseModel):
    """Список проектов"""
    projects: List[ProjectResponse] = Field(..., description="Список проектов")
    total_count: int = Field(..., description="Общее количество проектов")
    page: int = Field(..., description="Текущая страница")
    limit: int = Field(..., description="Количество на странице")

class ProjectCreateResponse(BaseModel):
    """Ответ на создание проекта"""
    success: bool = Field(True, description="Статус создания")
    message: str = Field(..., description="Сообщение")
    project_id: str = Field(..., description="ID созданного проекта")
    status: ProjectStatus = Field(..., description="Статус проекта")
    workspace: str = Field(..., description="Путь к рабочей области")

# === AI И ЧАТ ===

class AIResponse(BaseModel):
    """Ответ от AI"""
    content: str = Field(..., description="Содержимое ответа")
    provider: AIProvider = Field(..., description="Провайдер AI")
    model: str = Field(..., description="Модель AI")
    tokens_used: int = Field(..., description="Использовано токенов")
    cost_usd: float = Field(..., description="Стоимость в USD")
    response_time: float = Field(..., description="Время ответа в секундах")

class ChatStreamResponse(BaseModel):
    """Потоковый ответ чата"""
    type: str = Field(..., description="Тип сообщения")
    content: Optional[str] = Field(None, description="Содержимое")
    agent: Optional[str] = Field(None, description="Агент")
    progress: Optional[int] = Field(None, description="Прогресс (0-100)")
    timestamp: datetime = Field(default_factory=datetime.now, description="Время")

class AIUsageStatsResponse(BaseModel):
    """Статистика использования AI"""
    total_requests: int = Field(..., description="Общее количество запросов")
    total_tokens: int = Field(..., description="Общее количество токенов")
    total_cost: float = Field(..., description="Общая стоимость")
    success_rate: float = Field(..., description="Процент успешных запросов")
    providers: Dict[str, Dict[str, Any]] = Field(..., description="Статистика по провайдерам")

# === API КЛЮЧИ ===

class APIKeyResponse(BaseModel):
    """Информация об API ключе"""
    id: str = Field(..., description="ID ключа")
    provider: AIProvider = Field(..., description="Провайдер")
    key_name: str = Field(..., description="Название ключа")
    api_key_last_4: str = Field(..., description="Последние 4 символа")
    is_active: bool = Field(..., description="Активность ключа")
    last_used_at: Optional[datetime] = Field(None, description="Последнее использование")
    created_at: datetime = Field(..., description="Дата создания")

class APIKeyListResponse(BaseModel):
    """Список API ключей"""
    keys: List[APIKeyResponse] = Field(..., description="Список ключей")
    total_count: int = Field(..., description="Общее количество ключей")

class APIKeyValidationResponse(BaseModel):
    """Ответ на валидацию API ключей"""
    validation_results: Dict[str, bool] = Field(..., description="Результаты валидации")
    valid_keys: List[str] = Field(..., description="Валидные ключи")
    invalid_keys: List[str] = Field(..., description="Невалидные ключи")

# === НАСТРОЙКИ ===

class UserSettingsResponse(BaseModel):
    """Настройки пользователя"""
    default_model: str = Field(..., description="Модель по умолчанию")
    default_provider: AIProvider = Field(..., description="Провайдер по умолчанию")
    auto_export: bool = Field(..., description="Автоматический экспорт")
    notifications_email: bool = Field(..., description="Email уведомления")
    notifications_generation: bool = Field(..., description="Уведомления о генерации")
    theme: str = Field(..., description="Тема интерфейса")

# === ФАЙЛЫ ===

class FileInfoResponse(BaseModel):
    """Информация о файле"""
    file_path: str = Field(..., description="Путь к файлу")
    content: str = Field(..., description="Содержимое файла")
    size: int = Field(..., description="Размер файла")
    last_modified: datetime = Field(..., description="Дата последнего изменения")

class FileTreeResponse(BaseModel):
    """Структура файлов проекта"""
    project_id: str = Field(..., description="ID проекта")
    files: Dict[str, Any] = Field(..., description="Структура файлов")
    updated_at: datetime = Field(..., description="Дата обновления")

# === ЭКСПОРТ ===

class ExportResponse(BaseModel):
    """Ответ на экспорт проекта"""
    success: bool = Field(True, description="Статус экспорта")
    message: str = Field(..., description="Сообщение")
    download_url: str = Field(..., description="URL для скачивания")
    file_size: int = Field(..., description="Размер файла")
    expires_at: datetime = Field(..., description="Время истечения ссылки")

# === ПРОВАЙДЕРЫ ===

class AIProviderInfoResponse(BaseModel):
    """Информация о AI провайдере"""
    id: str = Field(..., description="ID провайдера")
    name: str = Field(..., description="Название")
    display_name: str = Field(..., description="Отображаемое название")
    description: str = Field(..., description="Описание")
    website: str = Field(..., description="Веб-сайт")
    requires_key: bool = Field(..., description="Требует API ключ")
    free_models: List[str] = Field(..., description="Бесплатные модели")

class AIProvidersResponse(BaseModel):
    """Список AI провайдеров"""
    providers: List[AIProviderInfoResponse] = Field(..., description="Список провайдеров")

# === ЗДОРОВЬЕ СИСТЕМЫ ===

class HealthCheckResponse(BaseModel):
    """Ответ проверки здоровья"""
    status: str = Field(..., description="Статус системы")
    timestamp: datetime = Field(default_factory=datetime.now, description="Время проверки")
    version: str = Field(..., description="Версия приложения")
    uptime: float = Field(..., description="Время работы в секундах")
    services: Dict[str, str] = Field(..., description="Статус сервисов")

class DetailedHealthResponse(BaseModel):
    """Детальная проверка здоровья"""
    status: str = Field(..., description="Общий статус")
    timestamp: datetime = Field(default_factory=datetime.now, description="Время проверки")
    version: str = Field(..., description="Версия приложения")
    uptime: float = Field(..., description="Время работы в секундах")
    services: Dict[str, str] = Field(..., description="Статус сервисов")
    external_services: Dict[str, str] = Field(..., description="Статус внешних сервисов")
    active_projects: int = Field(..., description="Количество активных проектов")
    memory_usage: Dict[str, Any] = Field(..., description="Использование памяти")
    disk_usage: Dict[str, Any] = Field(..., description="Использование диска")

# === МЕТРИКИ ===

class MetricsResponse(BaseModel):
    """Метрики системы"""
    timestamp: datetime = Field(default_factory=datetime.now, description="Время метрик")
    requests_total: int = Field(..., description="Общее количество запросов")
    requests_per_second: float = Field(..., description="Запросов в секунду")
    response_time_avg: float = Field(..., description="Среднее время ответа")
    error_rate: float = Field(..., description="Процент ошибок")
    active_users: int = Field(..., description="Активные пользователи")
    active_projects: int = Field(..., description="Активные проекты")