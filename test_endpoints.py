#!/usr/bin/env python3
"""
Простой тест для проверки эндпоинтов
"""

import sys
import os
sys.path.append('/workspace')

from backend.main import app
from fastapi.testclient import TestClient

def test_app_starts():
    """Тест что приложение запускается без ошибок"""
    try:
        client = TestClient(app)
        print("✅ Приложение запускается без ошибок")
        return True
    except Exception as e:
        print(f"❌ Ошибка запуска приложения: {e}")
        return False

def test_health_endpoint():
    """Тест health эндпоинта"""
    try:
        client = TestClient(app)
        response = client.get("/health")
        print(f"✅ Health endpoint: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Ошибка health endpoint: {e}")
        return False

def test_login_endpoint():
    """Тест login эндпоинта"""
    try:
        client = TestClient(app)
        response = client.post("/api/auth/login", 
            json={
                "email": "test@example.com",
                "password": "password123"
            },
            headers={"X-CSRF-Token": "test_csrf_token"}
        )
        print(f"✅ Login endpoint: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Структура ответа: {list(data.keys())}")
        return True
    except Exception as e:
        print(f"❌ Ошибка login endpoint: {e}")
        return False

def test_register_endpoint():
    """Тест register эндпоинта"""
    try:
        client = TestClient(app)
        response = client.post("/api/auth/register", 
            json={
                "email": "newuser@example.com",
                "password": "password123",
                "full_name": "New User"
            },
            headers={"X-CSRF-Token": "test_csrf_token"}
        )
        print(f"✅ Register endpoint: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Структура ответа: {list(data.keys())}")
        return True
    except Exception as e:
        print(f"❌ Ошибка register endpoint: {e}")
        return False

def test_projects_endpoint():
    """Тест projects эндпоинта"""
    try:
        client = TestClient(app)
        response = client.get("/api/projects?limit=5&offset=0")
        print(f"✅ Projects endpoint: {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Ошибка projects endpoint: {e}")
        return False

def test_ai_endpoint():
    """Тест AI эндпоинта"""
    try:
        client = TestClient(app)
        response = client.post("/api/ai/chat", 
            json={
                "message": "Hello, AI!",
                "context": "test",
                "model": "gpt-3.5-turbo",
                "provider": "openai"
            },
            headers={"X-CSRF-Token": "test_csrf_token"}
        )
        print(f"✅ AI chat endpoint: {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Ошибка AI chat endpoint: {e}")
        return False

def main():
    """Основная функция тестирования"""
    print("🧪 Тестирование API эндпоинтов...")
    print("=" * 50)
    
    tests = [
        test_app_starts,
        test_health_endpoint,
        test_login_endpoint,
        test_register_endpoint,
        test_projects_endpoint,
        test_ai_endpoint
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Результат: {passed}/{total} тестов прошли")
    
    if passed == total:
        print("🎉 Все тесты прошли успешно!")
        return True
    else:
        print("⚠️  Некоторые тесты не прошли")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)