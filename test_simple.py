#!/usr/bin/env python3
"""
Простой тест для проверки основных функций
"""

import asyncio
import httpx

async def test_basic():
    """Базовый тест"""
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Тест корневого эндпоинта
        print("1. Тестируем корневой эндпоинт...")
        try:
            response = await client.get("http://localhost:8001/")
            print(f"   Статус: {response.status_code}")
            if response.status_code == 200:
                print("   ✅ Корневой эндпоинт работает")
            else:
                print("   ❌ Корневой эндпоинт не работает")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # Тест health
        print("2. Тестируем health...")
        try:
            response = await client.get("http://localhost:8001/health")
            print(f"   Статус: {response.status_code}")
            if response.status_code == 200:
                print("   ✅ Health работает")
            else:
                print("   ❌ Health не работает")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # Тест login
        print("3. Тестируем login...")
        try:
            response = await client.post(
                "http://localhost:8001/api/auth/login",
                json={"email": "test@example.com", "password": "test"},
                timeout=5.0
            )
            print(f"   Статус: {response.status_code}")
            if response.status_code == 200:
                print("   ✅ Login работает")
                data = response.json()
                print(f"   Ответ: {data}")
            else:
                print("   ❌ Login не работает")
                print(f"   Ответ: {response.text}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")

if __name__ == "__main__":
    asyncio.run(test_basic())