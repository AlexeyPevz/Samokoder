#!/usr/bin/env python3
"""
Детальный тест всех эндпоинтов API
"""

import sys
import os
sys.path.append('/workspace')

from backend.main import app
from fastapi.testclient import TestClient

def _get_application_routes():
    """Получает все маршруты из приложения"""
    routes = []
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            for method in route.methods:
                if method != 'HEAD':  # Пропускаем HEAD
                    routes.append(f"{method} {route.path}")
    return routes

def _print_routes_info(routes):
    """Выводит информацию о найденных маршрутах"""
    print("🔍 Найденные эндпоинты в приложении:")
    for route in sorted(routes):
        print(f"  {route}")
    print(f"\n📊 Всего эндпоинтов: {len(routes)}")

def _get_test_cases():
    """Возвращает список тестовых случаев"""
    return [
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
    ]

def _test_endpoint(client, method, path):
    """Тестирует отдельный эндпоинт"""
    try:
        if method == "GET":
            response = client.get(path)
        elif method == "POST":
            response = client.post(path, json={})
        elif method == "PUT":
            response = client.put(path, json={})
        elif method == "DELETE":
            response = client.delete(path)
        else:
            print(f"❌ Неподдерживаемый метод: {method}")
            return False
        
        print(f"  {method} {path}: {response.status_code}")
        return response.status_code < 500
    except Exception as e:
        print(f"  {method} {path}: ERROR - {e}")
        return False

def test_all_endpoints():
    """Тест всех эндпоинтов из спецификации"""
    client = TestClient(app)
    
    # Получаем маршруты и выводим информацию
    routes = _get_application_routes()
    _print_routes_info(routes)
    
    # Получаем тестовые случаи
    test_cases = _get_test_cases()
    
    print(f"\n🧪 Тестирую {len(test_cases)} эндпоинтов...")
    success_count = 0
    
    for method, path in test_cases:
        if _test_endpoint(client, method, path):
            success_count += 1
    
    print(f"\n📊 Результаты: {success_count}/{len(test_cases)} эндпоинтов работают")
    return success_count == len(test_cases)

if __name__ == "__main__":
    test_all_endpoints()