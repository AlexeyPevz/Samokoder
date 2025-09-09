#!/usr/bin/env python3
"""
Скрипт для запуска сервера Самокодер
"""

import uvicorn
import os
import sys
from pathlib import Path

# Добавляем корневую директорию в Python path
root_dir = Path(__file__).parent
sys.path.insert(0, str(root_dir))

from config.settings import settings

def main():
    """Запуск сервера разработки"""
    
    print("🚀 Запуск Samokoder Backend API...")
    print(f"📍 Host: {settings.host}")
    print(f"🔌 Port: {settings.port}")
    print(f"🌍 Environment: {settings.environment}")
    print(f"🐛 Debug: {settings.debug}")
    print(f"📚 Docs: http://{settings.host}:{settings.port}/docs")
    print("-" * 50)
    
    # Проверяем наличие .env файла
    if not os.path.exists(".env"):
        print("⚠️  Внимание: файл .env не найден!")
        print("📋 Скопируйте .env.example в .env и заполните переменные")
        print("💡 cp .env.example .env")
        return
    
    # Проверяем обязательные переменные
    required_vars = [
        "SUPABASE_URL",
        "SUPABASE_ANON_KEY", 
        "API_ENCRYPTION_KEY"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not getattr(settings, var.lower(), None):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Отсутствуют обязательные переменные окружения:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\n📋 Заполните эти переменные в файле .env")
        return
    
    # Запускаем сервер
    try:
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
        sys.exit(1)

if __name__ == "__main__":
    main()