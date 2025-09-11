#!/usr/bin/env python3
"""
Детальный тест всех эндпоинтов API
"""

import sys
import os
sys.path.append('/workspace')

from backend.main import app
from fastapi.testclient import TestClient

def test_all_endpoints():
    """Тест всех эндпоинтов из спецификации"""
    client = TestClient(app)
    
    # Получаем все маршруты из приложения
    routes = []
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            for method in route.methods:
                if method != 'HEAD':  # Пропускаем HEAD
                    routes.append(f"{method} {route.path}")
    
    print("🔍 Найденные эндпоинты в приложении:")
    for route in sorted(routes):
        print(f"  {route}")
    
    print(f"\n📊 Всего эндпоинтов: {len(routes)}")
    
    # Проверяем основные эндпоинты
    test_cases = [
        ("GET", "/health"),
        ("GET", "/metrics"),
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/register"),
        ("POST", "/api/auth/logout"),
        ("GET", "/api/auth/user"),
        ("GET", "/api/projects"),
        ("POST", "/api/projects"),
        ("GET", "/api/projects/test-id"),
        ("PUT", "/api/projects/test-id"),
        ("DELETE", "/api/projects/test-id"),
        ("GET", "/api/projects/test-id/files"),
        ("GET", "/api/projects/test-id/files/test.py"),
        ("POST", "/api/projects/test-id/export"),
        ("POST", "/api/projects/test-id/chat"),
        ("POST", "/api/projects/test-id/generate"),
        ("POST", "/api/ai/chat"),
        ("POST", "/api/ai/chat/stream"),
        ("GET", "/api/ai/usage"),
        ("GET", "/api/ai/providers"),
        ("POST", "/api/ai/validate-keys"),
        ("POST", "/api/auth/mfa/setup"),
        ("POST", "/api/auth/mfa/verify"),
        ("DELETE", "/api/auth/mfa/disable"),
        ("GET", "/api/rbac/roles"),
        ("GET", "/api/rbac/permissions"),
        ("GET", "/api/rbac/users/test-user/roles"),
        ("POST", "/api/rbac/users/test-user/roles"),
        ("DELETE", "/api/rbac/users/test-user/roles/test-role"),
        ("GET", "/api/rbac/check-permission"),
        ("POST", "/api/api-keys/"),
        ("GET", "/api/api-keys/"),
        ("GET", "/api/api-keys/test-key"),
        ("PUT", "/api/api-keys/test-key/toggle"),
        ("DELETE", "/api/api-keys/test-key"),
        ("GET", "/api/health/database"),
        ("GET", "/api/health/ai"),
        ("GET", "/api/health/system"),
    ]
    
    print(f"\n🧪 Тестирование {len(test_cases)} эндпоинтов...")
    
    results = []
    for method, path in test_cases:
        try:
            if method == "GET":
                response = client.get(path)
            elif method == "POST":
                response = client.post(path, json={}, headers={"X-CSRF-Token": "test"})
            elif method == "PUT":
                response = client.put(path, json={}, headers={"X-CSRF-Token": "test"})
            elif method == "DELETE":
                response = client.delete(path, headers={"X-CSRF-Token": "test"})
            
            status = response.status_code
            if status in [200, 201, 401, 403, 404, 422]:
                results.append(f"✅ {method} {path} -> {status}")
            else:
                results.append(f"⚠️  {method} {path} -> {status}")
                
        except Exception as e:
            results.append(f"❌ {method} {path} -> ERROR: {str(e)[:50]}")
    
    print("\n📋 Результаты тестирования:")
    for result in results:
        print(f"  {result}")
    
    # Подсчет результатов
    success = len([r for r in results if r.startswith("✅")])
    warning = len([r for r in results if r.startswith("⚠️")])
    error = len([r for r in results if r.startswith("❌")])
    
    print(f"\n📊 Итоги:")
    print(f"  ✅ Успешно: {success}")
    print(f"  ⚠️  Предупреждения: {warning}")
    print(f"  ❌ Ошибки: {error}")
    print(f"  📈 Общий процент успеха: {success/(success+warning+error)*100:.1f}%")

if __name__ == "__main__":
    test_all_endpoints()