"""
Configuration management
"""
from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    """Application settings with fallback values and validation"""
    
    # Supabase - with fallback for development
    supabase_url: str = "https://example.supabase.co"
    supabase_anon_key: str = "example_anon_key"
    supabase_service_role_key: str = "example_service_key"
    
    # API Encryption - with fallback for development
    api_encryption_key: str = "dev_encryption_key_32_chars_minimum"
    api_encryption_salt: str = "dev_salt_16_chars"
    
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
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    
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
    
    # Security - with fallback for development
    secret_key: str = "dev_secret_key_32_chars_minimum"
    access_token_expire_minutes: int = 30
    
    # Database
    database_host: str = "localhost"
    database_port: int = 5432
    database_name: str = "samokoder"
    database_user: str = "postgres"
    database_password: str = "password"
    
    # Rate Limiting (detailed)
    rate_limit_auth_max_requests: int = 10
    rate_limit_auth_window_seconds: int = 60
    rate_limit_api_max_requests: int = 100
    rate_limit_api_window_seconds: int = 60
    rate_limit_ai_max_requests: int = 20
    rate_limit_ai_window_seconds: int = 60
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": False
    }
    
    def validate_configuration(self) -> None:
        """Validate critical configuration settings"""
        errors = []
        
        # Validate encryption key length
        if len(self.api_encryption_key) < 32:
            errors.append("API_ENCRYPTION_KEY must be at least 32 characters")
        
        # Validate secret key length
        if len(self.secret_key) < 32:
            errors.append("SECRET_KEY must be at least 32 characters")
        
        # Production-specific validations
        if self.environment == "production":
            if self.debug:
                errors.append("DEBUG must be False in production")
            if self.supabase_url.endswith("example.supabase.co"):
                errors.append("SUPABASE_URL must be configured for production")
            if self.api_encryption_key.startswith("dev_"):
                errors.append("API_ENCRYPTION_KEY must be production-ready")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")

# Глобальный экземпляр настроек с валидацией
settings = Settings()

# Валидируем конфигурацию при инициализации
try:
    settings.validate_configuration()
except ValueError as e:
    import sys
    print(f"❌ Configuration Error: {e}")
    if settings.environment == "production":
        sys.exit(1)
    else:
        print("⚠️  Running in development mode with fallback values")