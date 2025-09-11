#!/usr/bin/env python3
"""
Скрипт для анализа реальных структур данных API
"""

import json
import inspect
from backend.main import app
from backend.models.requests import LoginRequest, RegisterRequest, ChatRequest
from backend.models.responses import LoginResponse, RegisterResponse, AIResponse

def analyze_endpoint_signatures():
    """Анализ сигнатур эндпоинтов"""
    print("=== АНАЛИЗ СИГНАТУР ЭНДПОИНТОВ ===\n")
    
    # Получаем все эндпоинты из FastAPI app
    routes = []
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            for method in route.methods:
                if method != 'HEAD':  # Игнорируем HEAD
                    routes.append({
                        'method': method,
                        'path': route.path,
                        'endpoint': route.endpoint
                    })
    
    # Группируем по путям
    endpoints = {}
    for route in routes:
        path = route['path']
        if path not in endpoints:
            endpoints[path] = []
        endpoints[path].append(route)
    
    print(f"Найдено {len(endpoints)} уникальных путей:")
    for path, methods in endpoints.items():
        print(f"\n{path}:")
        for route in methods:
            print(f"  {route['method']}: {route['endpoint'].__name__}")
            
            # Анализируем параметры функции
            sig = inspect.signature(route['endpoint'])
            print(f"    Параметры: {list(sig.parameters.keys())}")
            
            # Анализируем аннотации типов
            for param_name, param in sig.parameters.items():
                if param.annotation != inspect.Parameter.empty:
                    print(f"      {param_name}: {param.annotation}")
    
    return endpoints

def analyze_models():
    """Анализ моделей данных"""
    print("\n=== АНАЛИЗ МОДЕЛЕЙ ДАННЫХ ===\n")
    
    models = [
        ('LoginRequest', LoginRequest),
        ('RegisterRequest', RegisterRequest), 
        ('ChatRequest', ChatRequest),
        ('LoginResponse', LoginResponse),
        ('RegisterResponse', RegisterResponse),
        ('AIResponse', AIResponse)
    ]
    
    for name, model in models:
        print(f"{name}:")
        if hasattr(model, '__fields__'):
            # Pydantic v1
            fields = model.__fields__
        elif hasattr(model, 'model_fields'):
            # Pydantic v2
            fields = model.model_fields
        else:
            print("  Не Pydantic модель")
            continue
            
        for field_name, field_info in fields.items():
            field_type = getattr(field_info, 'annotation', 'Unknown')
            required = getattr(field_info, 'is_required', False)
            print(f"  {field_name}: {field_type} {'(required)' if required else '(optional)'}")

def analyze_real_responses():
    """Анализ реальных структур ответов из кода"""
    print("\n=== АНАЛИЗ РЕАЛЬНЫХ СТРУКТУР ОТВЕТОВ ===\n")
    
    # Анализируем login эндпоинт
    print("POST /api/auth/login:")
    print("  Реальная структура ответа:")
    print("  {")
    print("    'message': str,")
    print("    'user': {")
    print("      'id': str,")
    print("      'email': str,")
    print("      'created_at': str")
    print("    },")
    print("    'session': {")
    print("      'access_token': str,")
    print("      'token_type': str")
    print("    }")
    print("  }")
    
    print("\n  Ожидаемая структура (из спецификации):")
    print("  {")
    print("    'success': bool,")
    print("    'message': str,")
    print("    'user': UserResponse,")
    print("    'access_token': str,")
    print("    'token_type': str,")
    print("    'expires_in': int")
    print("  }")
    
    print("\n  ❌ РАСХОЖДЕНИЕ: Полностью разные структуры!")
    
    # Анализируем projects эндпоинт
    print("\nGET /api/projects:")
    print("  Реальная структура ответа:")
    print("  {")
    print("    'projects': list,")
    print("    'total_count': int")
    print("  }")
    
    print("\n  Ожидаемая структура (из спецификации):")
    print("  {")
    print("    'projects': list,")
    print("    'total_count': int,")
    print("    'page': int,")
    print("    'limit': int")
    print("  }")
    
    print("\n  ❌ РАСХОЖДЕНИЕ: Отсутствуют поля page и limit!")
    
    # Анализируем AI chat эндпоинт
    print("\nPOST /api/ai/chat:")
    print("  Реальная структура ответа:")
    print("  {")
    print("    'content': str,")
    print("    'provider': str,")
    print("    'model': str,")
    print("    'tokens_used': int,")
    print("    'cost_usd': float,")
    print("    'response_time': float")
    print("  }")
    
    print("\n  Ожидаемая структура (из спецификации):")
    print("  {")
    print("    'content': str,")
    print("    'provider': AIProvider,")
    print("    'model': str,")
    print("    'usage': {")
    print("      'prompt_tokens': int,")
    print("      'completion_tokens': int,")
    print("      'total_tokens': int,")
    print("      'prompt_cost': float,")
    print("      'completion_cost': float,")
    print("      'total_cost': float")
    print("    },")
    print("    'response_time': float")
    print("  }")
    
    print("\n  ❌ РАСХОЖДЕНИЕ: tokens_used/cost_usd vs usage объект!")

def check_missing_endpoints():
    """Проверка отсутствующих эндпоинтов"""
    print("\n=== ПРОВЕРКА ОТСУТСТВУЮЩИХ ЭНДПОИНТОВ ===\n")
    
    # Получаем все пути из app
    app_paths = set()
    for route in app.routes:
        if hasattr(route, 'path'):
            app_paths.add(route.path)
    
    # Эндпоинты из спецификации
    spec_endpoints = [
        "/api/auth/me",
        "/api/projects/{project_id}",  # PUT метод
        "/api/ai/chat/stream",
        "/api/health/database",
        "/api/health/ai", 
        "/api/health/system",
        "/api/auth/mfa/setup",
        "/api/auth/mfa/verify",
        "/api/auth/mfa/disable",
        "/api/rbac/roles",
        "/api/rbac/permissions",
        "/api/rbac/users/{user_id}/roles",
        "/api/rbac/check-permission",
        "/api/api-keys/",
        "/api/api-keys/{key_id}"
    ]
    
    missing = []
    for endpoint in spec_endpoints:
        if endpoint not in app_paths:
            missing.append(endpoint)
    
    print(f"Отсутствующих эндпоинтов: {len(missing)}")
    for endpoint in missing:
        print(f"  ❌ {endpoint}")

def main():
    """Основная функция"""
    print("ДЕТАЛЬНЫЙ АНАЛИЗ API РАСХОЖДЕНИЙ")
    print("=" * 50)
    
    endpoints = analyze_endpoint_signatures()
    analyze_models()
    analyze_real_responses()
    check_missing_endpoints()
    
    print("\n" + "=" * 50)
    print("ЗАКЛЮЧЕНИЕ:")
    print("Обнаружены критические расхождения между спецификацией и реализацией!")
    print("Требуется серьезная работа по синхронизации.")

if __name__ == "__main__":
    main()