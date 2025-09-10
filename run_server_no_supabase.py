#!/usr/bin/env python3
"""
Скрипт для запуска сервера Самокодер без Supabase
Для тестирования и разработки
"""

import uvicorn
import os
import sys
from pathlib import Path
import logging

# Добавляем корневую директорию в Python path
root_dir = Path(__file__).parent
sys.path.insert(0, str(root_dir))

from config.settings import settings

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Запуск сервера разработки без Supabase"""
    
    print("🚀 Запуск Samokoder Backend API (без Supabase)...")
    print(f"📍 Host: {settings.host}")
    print(f"🔌 Port: {settings.port}")
    # Используем другой порт если 8000 занят
    if settings.port == 8000:
        settings.port = 8001
    print(f"🌍 Environment: {settings.environment}")
    print(f"🐛 Debug: {settings.debug}")
    print(f"📚 Docs: http://{settings.host}:{settings.port}/docs")
    print("-" * 50)
    
    # Проверяем наличие .env файла
    if not os.path.exists(".env"):
        print("⚠️  Внимание: файл .env не найден!")
        print("📋 Создаем базовый .env файл...")
        
        # Создаем базовый .env файл
        env_content = """# Supabase Configuration (заглушки)
SUPABASE_URL=https://example.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example

# API Encryption
API_ENCRYPTION_KEY=QvXgcQGd8pz8YETjvWhCLnAJ5SHD2A6uQzBn3_5dNaE

# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=true
ENVIRONMENT=development

# CORS
CORS_ORIGINS=["http://localhost:3000", "http://localhost:5173"]

# Redis
REDIS_URL=redis://localhost:6379

# Monitoring
SENTRY_DSN=

# System API Keys (optional fallback)
SYSTEM_OPENROUTER_KEY=
SYSTEM_OPENAI_KEY=
SYSTEM_ANTHROPIC_KEY=
SYSTEM_GROQ_KEY=
"""
        
        with open(".env", "w") as f:
            f.write(env_content)
        print("✅ Базовый .env файл создан")
    
    # Проверяем обязательные переменные (только для шифрования)
    if not getattr(settings, 'api_encryption_key', None):
        print("❌ Отсутствует API_ENCRYPTION_KEY")
        print("📋 Добавьте API_ENCRYPTION_KEY в файл .env")
        return
    
    # Пропускаем проверку Supabase - работаем без него
    print("⚠️  Supabase проверка пропущена - работаем в режиме без БД")
    print("💡 Для полной функциональности настройте Supabase")
    
    # Проверяем директории
    for dir_path in ["exports", "workspaces"]:
        try:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            print(f"✅ Директория {dir_path} готова")
        except Exception as e:
            print(f"❌ Ошибка создания директории {dir_path}: {e}")
            logger.error(f"Directory creation error: {e}")
            return
    
    # Запускаем сервер
    try:
        print("\n🚀 Запуск сервера...")
        print("💡 Сервер работает в режиме без Supabase")
        print("💡 API ключи можно добавлять через интерфейс")
        print("💡 Некоторые функции могут работать в режиме симуляции")
        print("-" * 50)
        
        uvicorn.run(
            "backend.main:app",
            host=settings.host,
            port=settings.port,
            reload=settings.debug,
            log_level=settings.log_level.lower(),
            access_log=True
        )
    except KeyboardInterrupt:
        print("\n👋 Сервер остановлен пользователем")
    except Exception as e:
        print(f"❌ Ошибка запуска сервера: {e}")
        logger.error(f"Server startup error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()