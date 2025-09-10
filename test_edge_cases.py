#!/usr/bin/env python3
"""
Тест edge cases и потенциальных багов
"""

import asyncio
import httpx
import json
import uuid
from datetime import datetime

BASE_URL = "http://localhost:8001"

async def test_edge_cases():
    """Тестирование edge cases"""
    
    print("🔍 EDGE CASES TESTING")
    print("=" * 50)
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        
        # 1. Тест с пустыми данными
        print("1. Тестируем пустые данные...")
        try:
            response = await client.post(
                f"{BASE_URL}/api/auth/login",
                json={}
            )
            if response.status_code == 400:
                print("   ✅ Пустые данные обработаны корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 2. Тест с невалидным JSON
        print("2. Тестируем невалидный JSON...")
        try:
            response = await client.post(
                f"{BASE_URL}/api/auth/login",
                content="invalid json",
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 422:
                print("   ✅ Невалидный JSON обработан корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 3. Тест с очень длинными данными
        print("3. Тестируем очень длинные данные...")
        try:
            long_string = "x" * 10000
            response = await client.post(
                f"{BASE_URL}/api/auth/login",
                json={"email": long_string, "password": long_string}
            )
            if response.status_code in [200, 400, 422]:
                print("   ✅ Длинные данные обработаны корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 4. Тест с SQL injection попытками
        print("4. Тестируем SQL injection...")
        try:
            response = await client.post(
                f"{BASE_URL}/api/auth/login",
                json={"email": "'; DROP TABLE users; --", "password": "test"}
            )
            if response.status_code in [200, 400, 401]:
                print("   ✅ SQL injection попытка обработана корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 5. Тест с XSS попытками
        print("5. Тестируем XSS попытки...")
        try:
            response = await client.post(
                f"{BASE_URL}/api/auth/login",
                json={"email": "<script>alert('xss')</script>", "password": "test"}
            )
            if response.status_code in [200, 400, 401]:
                print("   ✅ XSS попытка обработана корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 6. Тест с несуществующим проектом
        print("6. Тестируем несуществующий проект...")
        try:
            mock_token = f"mock_token_{uuid.uuid4()}"
            response = await client.get(
                f"{BASE_URL}/api/projects/nonexistent-project-id",
                headers={"Authorization": f"Bearer {mock_token}"}
            )
            if response.status_code == 404:
                print("   ✅ Несуществующий проект обработан корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 7. Тест с невалидным токеном
        print("7. Тестируем невалидный токен...")
        try:
            response = await client.get(
                f"{BASE_URL}/api/projects",
                headers={"Authorization": "Bearer invalid_token"}
            )
            if response.status_code == 401:
                print("   ✅ Невалидный токен обработан корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 8. Тест с отсутствующим токеном
        print("8. Тестируем отсутствующий токен...")
        try:
            response = await client.get(f"{BASE_URL}/api/projects")
            if response.status_code == 403:
                print("   ✅ Отсутствующий токен обработан корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 9. Тест с невалидным Content-Type
        print("9. Тестируем невалидный Content-Type...")
        try:
            response = await client.post(
                f"{BASE_URL}/api/auth/login",
                content='{"email":"test@example.com","password":"test"}',
                headers={"Content-Type": "text/plain"}
            )
            if response.status_code in [200, 400, 415]:
                print("   ✅ Невалидный Content-Type обработан корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        # 10. Тест с очень большим телом запроса
        print("10. Тестируем очень большое тело запроса...")
        try:
            large_data = {"email": "test@example.com", "password": "test", "extra": "x" * 1000000}
            response = await client.post(
                f"{BASE_URL}/api/auth/login",
                json=large_data,
                timeout=5.0
            )
            if response.status_code in [200, 400, 413]:
                print("   ✅ Большое тело запроса обработано корректно")
            else:
                print(f"   ❌ Неожиданный код: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
        
        print("\n" + "=" * 50)
        print("🎉 EDGE CASES TESTING ЗАВЕРШЕН")

if __name__ == "__main__":
    asyncio.run(test_edge_cases())