#!/usr/bin/env python3
"""
Скрипт для запуска сервера Самокодер (исправленная версия)
"""

import uvicorn
import os
import sys
from pathlib import Path
import logging

# Добавляем корневую директорию в Python path
root_dir = Path(__file__).parent
sys.path.insert(0, str(root_dir))

from config.settings_fixed import settings

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Запуск сервера разработки"""
    
    print("🚀 Запуск Samokoder Backend API (исправленная версия)...")
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
    
    # Проверяем доступность Supabase
    try:
        from supabase import create_client
        supabase = create_client(settings.supabase_url, settings.supabase_anon_key)
        # Тестируем подключение
        supabase.table("profiles").select("id").limit(1).execute()
        print("✅ Supabase подключение успешно")
    except Exception as e:
        print(f"❌ Ошибка подключения к Supabase: {e}")
        print("Проверьте правильность SUPABASE_URL и SUPABASE_ANON_KEY")
        logger.error(f"Supabase connection error: {e}")
        return
    
    # Проверяем доступность GPT-Pilot
    gpt_pilot_path = Path(settings.gpt_pilot_path)
    if not gpt_pilot_path.exists():
        print(f"⚠️  GPT-Pilot не найден по пути: {gpt_pilot_path}")
        print("Некоторые функции могут работать в режиме заглушек")
    else:
        print("✅ GPT-Pilot найден")
    
    # Проверяем директории
    for dir_path in [settings.export_storage_path, settings.workspace_storage_path]:
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
        uvicorn.run(
            "backend.main_fixed:app",
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