#!/usr/bin/env python3
"""
Простая настройка Supabase без внешних зависимостей
"""

import urllib.request
import urllib.parse
import json

# Настройки Supabase
SUPABASE_URL = "https://auhzhdndqyflfdfszapm.supabase.co"
SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF1aHpoZG5kcXlmbGZkZnN6YXBtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NzQ0ODcxNywiZXhwIjoyMDczMDI0NzE3fQ.xIJO7zl1hD4IN08oUV5vUWIAP71PEdn2yu_qfF7seQk"

def test_connection():
    """Тестируем подключение к Supabase"""
    print("🔍 Тестируем подключение к Supabase...")
    
    headers = {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        # Создаем запрос
        req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/", headers=headers)
        
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("✅ Подключение к Supabase успешно!")
                return True
            else:
                print(f"❌ Ошибка подключения: {response.status}")
                return False
                
    except Exception as e:
        print(f"❌ Ошибка подключения: {e}")
        return False

def get_sql_instructions():
    """Получаем инструкции по выполнению SQL"""
    print("\n📋 ИНСТРУКЦИИ ПО НАСТРОЙКЕ SUPABASE:")
    print("=" * 60)
    print("1. Перейдите в Supabase Dashboard:")
    print("   https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql")
    print("\n2. Скопируйте и выполните SQL скрипт из файла:")
    print("   /workspace/supabase_quick_setup.sql")
    print("\n3. После выполнения SQL скрипта запустите сервер:")
    print("   python3 run_server.py")
    print("\n4. Получите Service Role Key:")
    print("   Settings → API → service_role")
    print("\n5. Обновите .env файл:")
    print("   SUPABASE_SERVICE_ROLE_KEY=ваш_ключ")
    print("\n6. Ваш Service Role Key (уже есть):")
    print(f"   {SERVICE_KEY}")

def main():
    print("🚀 Настройка Supabase для проекта Самокодер")
    print("=" * 50)
    
    # Тестируем подключение
    if test_connection():
        print("\n✅ Supabase доступен!")
        get_sql_instructions()
    else:
        print("\n❌ Не удалось подключиться к Supabase")
        print("📋 Проверьте URL и ключи")

if __name__ == "__main__":
    main()