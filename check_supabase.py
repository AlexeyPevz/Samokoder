#!/usr/bin/env python3
"""
Проверка состояния Supabase после выполнения SQL
"""

import urllib.request
import urllib.parse
import json

# Настройки Supabase
SUPABASE_URL = "https://auhzhdndqyflfdfszapm.supabase.co"
SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF1aHpoZG5kcXlmbGZkZnN6YXBtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NzQ0ODcxNywiZXhwIjoyMDczMDI0NzE3fQ.xIJO7zl1hD4IN08oUV5vUWIAP71PEdn2yu_qfF7seQk"

def check_table(table_name):
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
                return True, "✅"
            else:
                return False, f"❌ (код: {response.status})"
                
    except Exception as e:
        return False, f"❌ (ошибка: {str(e)[:50]}...)"

def main():
    print("🔍 Проверка состояния Supabase")
    print("=" * 40)
    
    # Список таблиц для проверки
    tables = [
        "profiles",
        "user_settings", 
        "user_api_keys",
        "projects",
        "ai_providers",
        "ai_models",
        "api_usage_log",
        "subscription_limits"
    ]
    
    print("\n📋 Проверяем таблицы...")
    
    existing = 0
    missing = 0
    
    for table in tables:
        exists, status = check_table(table)
        print(f"{status} {table}")
        
        if exists:
            existing += 1
        else:
            missing += 1
    
    print(f"\n📊 Результат: {existing}/{len(tables)} таблиц создано")
    
    if missing == 0:
        print("\n🎉 Все таблицы созданы! Supabase готов к использованию!")
        print("\n🚀 Теперь можно запускать сервер:")
        print("   python3 run_server.py")
    else:
        print(f"\n⚠️  Необходимо создать {missing} таблиц")
        print("\n📋 Выполните SQL скрипт:")
        print("1. Перейдите в: https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql")
        print("2. Скопируйте содержимое файла: supabase_setup_fixed.sql")
        print("3. Вставьте в SQL Editor и нажмите 'Run'")
        print("4. Запустите этот скрипт снова: python3 check_supabase.py")

if __name__ == "__main__":
    main()