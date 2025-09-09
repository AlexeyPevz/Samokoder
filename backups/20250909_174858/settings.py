from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
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
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Создаем глобальный экземпляр настроек
settings = Settings()

# Создаем директории если их нет
os.makedirs(settings.export_storage_path, exist_ok=True)
os.makedirs(settings.workspace_storage_path, exist_ok=True)