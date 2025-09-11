"""
Тестовая конфигурация для отключения middleware и проблемных компонентов
"""

import os
from typing import List
from pydantic_settings import BaseSettings

class TestSettings(BaseSettings):
    """Настройки для тестового окружения"""
    
    # Основные настройки
    environment: str = "test"
    debug: bool = True
    
    # Отключаем все middleware для тестов
    disable_csrf: bool = True
    disable_sentry: bool = True
    disable_cors: bool = True
    disable_security_headers: bool = True
    disable_rate_limiting: bool = True
    
    # Базовые настройки
    host: str = "127.0.0.1"
    port: int = 8000
    
    # Supabase (mock для тестов)
    supabase_url: str = "https://test-project.supabase.co"
    supabase_service_key: str = "test-service-key"
    supabase_anon_key: str = "test-anon-key"
    
    # Redis (mock для тестов)
    redis_url: str = "redis://localhost:6379"
    
    # Security (тестовые ключи)
    secret_key: str = "test-secret-key-32-chars-long"
    session_secret_key: str = "test-session-secret-key-32-chars"
    session_timeout: int = 3600
    access_token_expire_minutes: int = 30
    
    # Database (пустая для тестов)
    database_url: str = ""
    database_pool_size: int = 5
    database_max_overflow: int = 10
    
    # CORS (отключен для тестов)
    cors_origins: List[str] = []
    
    # Monitoring (отключен для тестов)
    enable_metrics: bool = False
    metrics_port: int = 9090
    sentry_dsn: str = ""
    
    # GPT-Pilot
    gpt_pilot_path: str = "./samokoder-core"
    gpt_pilot_timeout: int = 300
    
    # AI Models
    default_model: str = "test-model"
    default_provider: str = "test-provider"
    
    # Project limits
    max_projects_per_user: int = 10
    max_file_size_bytes: int = 50 * 1024 * 1024
    
    # Backup (отключен для тестов)
    enable_backups: bool = False
    backup_interval_hours: int = 24
    
    # Storage paths
    export_storage_path: str = "./test_exports"
    workspace_storage_path: str = "./test_workspaces"
    
    # Logging
    log_level: str = "WARNING"  # Минимальное логирование для тестов
    
    class Config:
        env_file = ".env.test"
        case_sensitive = False

# Создаем тестовый экземпляр настроек
test_settings = TestSettings()

# Создаем директории для тестов
os.makedirs(test_settings.export_storage_path, exist_ok=True)
os.makedirs(test_settings.workspace_storage_path, exist_ok=True)