from pydantic_settings import BaseSettings
from typing import List
import os
from backend.core.exceptions import ConfigurationError

class Settings(BaseSettings):
    # Supabase
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str
    
    # API Encryption
    api_encryption_key: str
    api_encryption_salt: str
    
    # System API Keys (fallback)
    system_openrouter_key: str = ""
    system_openai_key: str = ""
    system_anthropic_key: str = ""
    system_groq_key: str = ""
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True
    environment: str = "development"
    
    # CORS
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:5173"
    cors_allow_credentials: bool = True
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string"""
        return [origin.strip() for origin in self.cors_allowed_origins.split(',') if origin.strip()]
    
    # Session Management
    session_secret_key: str
    session_timeout: int = 3600
    
    # File Storage
    max_file_size_mb: int = 50
    export_storage_path: str = "./exports"
    workspace_storage_path: str = "./workspaces"
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000
    
    # Logging
    log_level: str = "INFO"
    sentry_dsn: str = ""
    
    # Redis (для кэширования и rate limiting)
    redis_url: str = "redis://localhost:6379"
    
    # Security
    secret_key: str
    session_secret_key: str
    session_timeout: int = 3600
    access_token_expire_minutes: int = 30
    
    # Database
    database_url: str = ""
    database_pool_size: int = 10
    database_max_overflow: int = 20
    
    # Monitoring
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    # GPT-Pilot
    gpt_pilot_path: str = "./samokoder-core"
    gpt_pilot_timeout: int = 300  # 5 минут
    
    # AI Models
    default_model: str = "deepseek/deepseek-v3"
    default_provider: str = "openrouter"
    
    # Circuit Breaker Configuration
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 60
    circuit_breaker_success_threshold: int = 3
    circuit_breaker_timeout: int = 30
    circuit_breaker_ai_timeout: int = 60
    circuit_breaker_db_timeout: int = 10
    
    # CSP Configuration
    csp_connect_src: str = "'self' https://api.openai.com https://api.anthropic.com https://openrouter.ai"
    csp_default_src: str = "'self'"
    
    @property
    def csp_policy(self) -> str:
        """Generate Content Security Policy header"""
        return (
            f"default-src {self.csp_default_src}; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            f"connect-src {self.csp_connect_src}; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
    
    # Project limits
    max_projects_per_user: int = 10
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50MB
    
    # Backup
    enable_backups: bool = False
    backup_interval_hours: int = 24
    
    def model_post_init(self, __context) -> None:
        """Валидация конфигурации после инициализации"""
        # Проверка на демо ключи в продакшене
        if not self.debug:
            demo_keys = [
                self.system_openai_key, 
                self.system_anthropic_key,
                self.system_groq_key,
                self.system_openrouter_key
            ]
            
            for key in demo_keys:
                if key and ('demo' in key.lower() or 'test' in key.lower()):
                    raise ConfigurationError(
                        "Demo keys are not allowed in production environment. "
                        "Please provide real API keys."
                    )
        
        # Проверка обязательных полей в продакшене
        if not self.debug:
            if not self.database_url:
                raise ConfigurationError("Database URL is required in production")
            
            if not self.secret_key or len(self.secret_key) < 32:
                raise ConfigurationError("Secret key must be at least 32 characters in production")

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"

# Создаем глобальный экземпляр настроек
settings = Settings()

# Создаем директории если их нет
os.makedirs(settings.export_storage_path, exist_ok=True)
os.makedirs(settings.workspace_storage_path, exist_ok=True)

# Валидация настроек
def validate_settings():
    """Валидирует настройки при запуске"""
    errors = []
    
    if not settings.supabase_url:
        errors.append("SUPABASE_URL is required")
    
    if not settings.supabase_anon_key:
        errors.append("SUPABASE_ANON_KEY is required")
    
    if not settings.api_encryption_key:
        errors.append("API_ENCRYPTION_KEY is required")
    
    if len(settings.api_encryption_key) < 32:
        errors.append("API_ENCRYPTION_KEY must be at least 32 characters")
    
    if settings.environment == "production" and settings.debug:
        errors.append("DEBUG should be False in production")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")

# Валидируем настройки при импорте
try:
    validate_settings()
except ValueError as e:
    print(f"⚠️ Configuration warning: {e}")
    print("Some features may not work correctly.")
except Exception as e:
    print(f"⚠️ Configuration error: {e}")
    print("Please check your configuration.")