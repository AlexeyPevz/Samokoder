#!/usr/bin/env python3
"""
Запуск сервера в режиме разработки
Работает без полной настройки Supabase
"""

import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Добавляем путь к проекту
sys.path.insert(0, str(Path(__file__).parent))

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Главная функция запуска сервера"""
    
    print("🚀 Запуск Samokoder Backend API (режим разработки)...")
    
    # Проверяем наличие .env файла
    if not Path(".env").exists():
        print("❌ Файл .env не найден")
        print("💡 Скопируйте .env.example в .env и заполните переменные")
        return
    
    # Проверяем обязательные переменные
    required_vars = [
        "SUPABASE_URL",
        "SUPABASE_ANON_KEY", 
        "API_ENCRYPTION_KEY"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Отсутствуют обязательные переменные окружения:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\n📋 Заполните эти переменные в файле .env")
        return
    
    print("✅ Переменные окружения загружены")
    
    # Проверяем подключение к Supabase (без строгой проверки таблиц)
    try:
        from supabase import create_client
        supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_ANON_KEY"))
        print("✅ Supabase клиент создан (таблицы могут быть не созданы)")
    except Exception as e:
        print(f"❌ Ошибка создания Supabase клиента: {e}")
        print("Проверьте правильность SUPABASE_URL и SUPABASE_ANON_KEY")
        logger.error(f"Supabase client creation error: {e}")
        return
    
    # Проверяем директории
    for dir_path in ["./exports", "./workspaces"]:
        try:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            print(f"✅ Директория {dir_path} готова")
        except Exception as e:
            print(f"❌ Ошибка создания директории {dir_path}: {e}")
    
    print("\n🎉 Все проверки пройдены!")
    print("🚀 Запускаем сервер...")
    print("📚 API документация: http://localhost:8000/docs")
    print("🔍 Health check: http://localhost:8000/health")
    print("📊 Метрики: http://localhost:8000/metrics")
    print("\n⚠️  ВАЖНО: Для полной функциональности выполните SQL схему в Supabase")
    print("📋 Инструкции: см. SUPABASE_SETUP_INSTRUCTIONS.md")
    print("\n" + "="*60)
    
    # Запускаем сервер
    try:
        import uvicorn
        
        uvicorn.run(
            "backend.main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n👋 Сервер остановлен")
    except Exception as e:
        print(f"❌ Ошибка запуска сервера: {e}")
        logger.error(f"Server startup error: {e}")

if __name__ == "__main__":
    main()