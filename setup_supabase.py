#!/usr/bin/env python3
"""
Скрипт для настройки Supabase базы данных
Создание таблиц, RLS политик, начальных данных
"""

import asyncio
import os
from supabase import create_client, Client
from pathlib import Path

# Настройки Supabase
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "your-anon-key-here")

def setup_supabase():
    """Настройка Supabase базы данных"""
    
    print("🚀 Настройка Supabase базы данных...")
    
    try:
        # Создаем клиент
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        
        # Проверяем подключение
        print("🔍 Проверяем подключение к Supabase...")
        response = supabase.table("profiles").select("id").limit(1).execute()
        print("✅ Подключение к Supabase успешно!")
        
        # Читаем SQL схему
        schema_path = Path("database/schema.sql")
        if schema_path.exists():
            print("📄 Читаем SQL схему...")
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema_sql = f.read()
            
            print("⚠️  Внимание: SQL схему нужно выполнить вручную в Supabase Dashboard")
            print("📋 Перейдите в: https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql")
            print("📋 Скопируйте и выполните содержимое файла database/schema.sql")
            
            # Сохраняем схему в отдельный файл для удобства
            with open("supabase_setup.sql", 'w', encoding='utf-8') as f:
                f.write(schema_sql)
            
            print("✅ SQL схема сохранена в supabase_setup.sql")
        else:
            print("❌ Файл database/schema.sql не найден")
            return False
        
        # Проверяем, что таблицы созданы
        print("🔍 Проверяем создание таблиц...")
        
        tables_to_check = [
            "profiles",
            "user_settings", 
            "user_api_keys",
            "projects",
            "ai_providers",
            "ai_models",
            "api_usage_log",
            "subscription_limits"
        ]
        
        existing_tables = []
        missing_tables = []
        
        for table in tables_to_check:
            try:
                supabase.table(table).select("id").limit(1).execute()
                existing_tables.append(table)
                print(f"✅ Таблица {table} существует")
            except Exception as e:
                missing_tables.append(table)
                print(f"❌ Таблица {table} не найдена: {e}")
        
        if missing_tables:
            print(f"\n⚠️  Необходимо создать таблицы: {', '.join(missing_tables)}")
            print("📋 Выполните SQL схему в Supabase Dashboard")
            return False
        
        print(f"\n✅ Все таблицы созданы! ({len(existing_tables)}/{len(tables_to_check)})")
        
        # Проверяем начальные данные
        print("🔍 Проверяем начальные данные...")
        
        # Проверяем AI провайдеров
        providers = supabase.table("ai_providers").select("*").execute()
        if providers.data:
            print(f"✅ AI провайдеры: {len(providers.data)} записей")
        else:
            print("⚠️  AI провайдеры не найдены")
        
        # Проверяем модели
        models = supabase.table("ai_models").select("*").execute()
        if models.data:
            print(f"✅ AI модели: {len(models.data)} записей")
        else:
            print("⚠️  AI модели не найдены")
        
        # Проверяем лимиты подписок
        limits = supabase.table("subscription_limits").select("*").execute()
        if limits.data:
            print(f"✅ Лимиты подписок: {len(limits.data)} записей")
        else:
            print("⚠️  Лимиты подписок не найдены")
        
        print("\n🎉 Настройка Supabase завершена!")
        print("📋 Следующие шаги:")
        print("1. Получите Service Role Key в Supabase Dashboard")
        print("2. Обновите SUPABASE_SERVICE_ROLE_KEY в .env файле")
        print("3. Запустите сервер: python run_server.py")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка настройки Supabase: {e}")
        return False

def get_service_role_key_instructions():
    """Инструкции по получению Service Role Key"""
    
    print("\n📋 Как получить Service Role Key:")
    print("1. Перейдите в Supabase Dashboard: https://supabase.com/dashboard")
    print("2. Выберите ваш проект: auhzhdndqyflfdfszapm")
    print("3. Перейдите в Settings → API")
    print("4. Скопируйте 'service_role' ключ")
    print("5. Обновите SUPABASE_SERVICE_ROLE_KEY в .env файле")
    print("\n⚠️  ВАЖНО: Service Role Key имеет полные права доступа!")
    print("   Никогда не коммитьте его в git!")

if __name__ == "__main__":
    print("🔧 Настройка проекта Самокодер")
    print("=" * 50)
    
    success = setup_supabase()
    
    if success:
        get_service_role_key_instructions()
        print("\n✅ Настройка завершена успешно!")
    else:
        print("\n❌ Настройка завершена с ошибками")
        print("📋 Проверьте подключение к Supabase и выполните SQL схему")