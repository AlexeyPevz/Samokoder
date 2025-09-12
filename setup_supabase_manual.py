#!/usr/bin/env python3
"""
Ручная настройка Supabase через REST API
"""

import requests
import json

# Настройки Supabase
import os
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "your-service-role-key-here")

def test_connection():
    """Тестируем подключение к Supabase"""
    print("🔍 Тестируем подключение к Supabase...")
    
    headers = {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        # Проверяем подключение через простой запрос
        response = requests.get(f"{SUPABASE_URL}/rest/v1/", headers=headers)
        
        if response.status_code == 200:
            print("✅ Подключение к Supabase успешно!")
            return True
        else:
            print(f"❌ Ошибка подключения: {response.status_code}")
            print(f"Ответ: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка подключения: {e}")
        return False

def check_tables():
    """Проверяем существующие таблицы"""
    print("\n🔍 Проверяем существующие таблицы...")
    
    headers = {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json"
    }
    
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
            response = requests.get(f"{SUPABASE_URL}/rest/v1/{table}?select=id&limit=1", headers=headers)
            
            if response.status_code == 200:
                existing_tables.append(table)
                print(f"✅ Таблица {table} существует")
            else:
                missing_tables.append(table)
                print(f"❌ Таблица {table} не найдена (код: {response.status_code})")
                
        except Exception as e:
            missing_tables.append(table)
            print(f"❌ Ошибка проверки таблицы {table}: {e}")
    
    return existing_tables, missing_tables

def get_sql_instructions():
    """Получаем инструкции по выполнению SQL"""
    print("\n📋 ИНСТРУКЦИИ ПО НАСТРОЙКЕ SUPABASE:")
    print("=" * 60)
    print("1. Перейдите в Supabase Dashboard:")
    print("   https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql")
    print("\n2. Скопируйте и выполните SQL скрипт из файла:")
    print("   /workspace/supabase_quick_setup.sql")
    print("\n3. После выполнения SQL скрипта запустите:")
    print("   python3 setup_supabase_manual.py --check")
    print("\n4. Получите Service Role Key:")
    print("   Settings → API → service_role")
    print("\n5. Обновите .env файл:")
    print("   SUPABASE_SERVICE_ROLE_KEY=ваш_ключ")

def main():
    print("🚀 Настройка Supabase для проекта Самокодер")
    print("=" * 50)
    
    # Тестируем подключение
    if not test_connection():
        print("\n❌ Не удалось подключиться к Supabase")
        print("📋 Проверьте URL и ключи")
        return
    
    # Проверяем таблицы
    existing_tables, missing_tables = check_tables()
    
    if missing_tables:
        print(f"\n⚠️  Необходимо создать таблицы: {', '.join(missing_tables)}")
        get_sql_instructions()
    else:
        print(f"\n✅ Все таблицы созданы! ({len(existing_tables)}/{len(existing_tables)})")
        print("🎉 Supabase готов к использованию!")

if __name__ == "__main__":
    main()