#!/usr/bin/env python3
"""
Выполнение SQL скрипта в Supabase через REST API
"""

import urllib.request
import urllib.parse
import json
import time

# Настройки Supabase
SUPABASE_URL = "https://auhzhdndqyflfdfszapm.supabase.co"
SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF1aHpoZG5kcXlmbGZkZnN6YXBtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NzQ0ODcxNywiZXhwIjoyMDczMDI0NzE3fQ.xIJO7zl1hD4IN08oUV5vUWIAP71PEdn2yu_qfF7seQk"

def execute_sql(sql_query):
    """Выполняет SQL запрос через Supabase REST API"""
    
    headers = {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json"
    }
    
    # Supabase не поддерживает выполнение произвольного SQL через REST API
    # Поэтому мы можем только проверить существование таблиц
    print("⚠️  Supabase REST API не поддерживает выполнение произвольного SQL")
    print("📋 Необходимо выполнить SQL вручную в Dashboard")
    
    return False

def check_table_exists(table_name):
    """Проверяет существование таблицы"""
    
    headers = {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/{table_name}?select=id&limit=1", headers=headers)
        
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                return True
            else:
                return False
                
    except Exception as e:
        return False

def main():
    print("🚀 Проверка состояния Supabase")
    print("=" * 40)
    
    # Читаем SQL скрипт
    try:
        with open("supabase_quick_setup.sql", "r", encoding="utf-8") as f:
            sql_content = f.read()
        print("✅ SQL скрипт прочитан")
    except Exception as e:
        print(f"❌ Ошибка чтения SQL скрипта: {e}")
        return
    
    # Проверяем существующие таблицы
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
    
    print("\n🔍 Проверяем существующие таблицы...")
    
    existing_tables = []
    missing_tables = []
    
    for table in tables_to_check:
        if check_table_exists(table):
            existing_tables.append(table)
            print(f"✅ Таблица {table} существует")
        else:
            missing_tables.append(table)
            print(f"❌ Таблица {table} не найдена")
    
    if missing_tables:
        print(f"\n⚠️  Необходимо создать таблицы: {', '.join(missing_tables)}")
        print("\n📋 ИНСТРУКЦИИ:")
        print("1. Перейдите в: https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql")
        print("2. Скопируйте содержимое файла supabase_quick_setup.sql")
        print("3. Вставьте в SQL Editor и нажмите 'Run'")
        print("4. После выполнения запустите этот скрипт снова")
    else:
        print(f"\n✅ Все таблицы созданы! ({len(existing_tables)}/{len(tables_to_check)})")
        print("🎉 Supabase готов к использованию!")

if __name__ == "__main__":
    main()