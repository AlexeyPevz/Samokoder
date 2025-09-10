"""
Configuration management
"""
from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Supabase
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str
    
    # API Encryption
    api_encryption_key: str
    api_encryption_salt: str = "samokoder_salt_2025"
    
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
    
    # Security
    secret_key: str = "QvXgcQGd8pz8YETjvWhCLnAJ5SHD2A6uQzBn3_5dNaE"
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
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Глобальный экземпляр настроек
settings = Settings()