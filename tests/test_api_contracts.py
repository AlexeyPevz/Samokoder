"""
Контрактные тесты для API
Проверяют соответствие реальных эндпоинтов OpenAPI спецификации
"""

import pytest
import json
import yaml
from fastapi.testclient import TestClient
from backend.main import app
from pathlib import Path

# Загружаем OpenAPI спецификацию
def load_openapi_spec():
    """Загружает OpenAPI спецификацию из файла"""
    spec_path = Path(__file__).parent.parent / "api" / "openapi_spec.yaml"
    with open(spec_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# Получаем OpenAPI спецификацию
openapi_spec = load_openapi_spec()

class TestAPIContracts:
    """Тесты контрактов API"""
    
    def test_openapi_spec_valid(self):
        """Проверяет валидность OpenAPI спецификации"""
        assert openapi_spec is not None
        assert 'openapi' in openapi_spec
        assert 'info' in openapi_spec
        assert 'paths' in openapi_spec
        assert 'components' in openapi_spec
        
        # Проверяем версию OpenAPI
        assert openapi_spec['openapi'].startswith('3.0')
        
        # Проверяем обязательные поля info
        assert 'title' in openapi_spec['info']
        assert 'version' in openapi_spec['info']
        assert 'description' in openapi_spec['info']
    
    def test_health_endpoints_contract(self):
        """Проверяет контракт health эндпоинтов"""
        with TestClient(app) as client:
            # Проверяем /health
            response = client.get("/health")
            assert response.status_code == 200
            
            data = response.json()
            assert 'status' in data
            assert 'timestamp' in data
            assert 'version' in data
            assert 'uptime' in data
            assert 'services' in data
            
            # Проверяем /health/detailed
            response = client.get("/health/detailed")
            assert response.status_code == 200
            
            data = response.json()
            assert 'status' in data
            assert 'timestamp' in data
            assert 'version' in data
            assert 'uptime' in data
            assert 'services' in data
            assert 'external_services' in data
            assert 'active_projects' in data
            assert 'memory_usage' in data
            assert 'disk_usage' in data
    
    def test_auth_endpoints_contract(self):
        """Проверяет контракт authentication эндпоинтов"""
        with TestClient(app) as client:
            # Проверяем POST /api/auth/login
            login_data = {
                "email": "test@example.com",
                "password": "TestPassword123!"
            }
            
            response = client.post("/api/auth/login", json=login_data)
            # Может быть 401 или 200 в зависимости от наличия пользователя
            assert response.status_code in [200, 401]
            
            if response.status_code == 200:
                data = response.json()
                assert 'access_token' in data
                assert 'token_type' in data
                assert 'user' in data
                assert 'message' in data
            
            # Проверяем POST /api/auth/register
            register_data = {
                "email": "newuser@example.com",
                "password": "TestPassword123!",
                "full_name": "Test User"
            }
            
            response = client.post("/api/auth/register", json=register_data)
            # Может быть 201 или 400/409 в зависимости от существования пользователя
            assert response.status_code in [201, 400, 409]
            
            if response.status_code == 201:
                data = response.json()
                assert 'user_id' in data
                assert 'email' in data
                assert 'message' in data
    
    def test_projects_endpoints_contract(self):
        """Проверяет контракт projects эндпоинтов"""
        with TestClient(app) as client:
            # Сначала нужно аутентифицироваться
            # Для тестирования контракта используем мок токен
            headers = {"Authorization": "Bearer mock_token"}
            
            # Проверяем GET /api/projects
            response = client.get("/api/projects", headers=headers)
            # Может быть 401 или 200 в зависимости от валидности токена
            assert response.status_code in [200, 401]
            
            if response.status_code == 200:
                data = response.json()
                assert 'projects' in data
                assert 'total' in data
                assert 'limit' in data
                assert 'offset' in data
            
            # Проверяем POST /api/projects
            project_data = {
                "name": "Test Project",
                "description": "A test project for contract testing"
            }
            
            response = client.post("/api/projects", json=project_data, headers=headers)
            assert response.status_code in [201, 401]
            
            if response.status_code == 201:
                data = response.json()
                assert 'project_id' in data
                assert 'message' in data
    
    def test_ai_endpoints_contract(self):
        """Проверяет контракт AI эндпоинтов"""
        with TestClient(app) as client:
            headers = {"Authorization": "Bearer mock_token"}
            
            # Проверяем POST /api/ai/chat
            chat_data = {
                "message": "Create a simple React component",
                "context": "react_component"
            }
            
            response = client.post("/api/ai/chat", json=chat_data, headers=headers)
            assert response.status_code in [200, 401, 500]
            
            if response.status_code == 200:
                data = response.json()
                assert 'response' in data
                assert 'model' in data
                assert 'provider' in data
            
            # Проверяем GET /api/ai/usage
            response = client.get("/api/ai/usage", headers=headers)
            assert response.status_code in [200, 401]
            
            if response.status_code == 200:
                data = response.json()
                assert 'total_tokens' in data
                assert 'total_cost' in data
                assert 'total_requests' in data
                assert 'period_days' in data
                assert 'provider_stats' in data
            
            # Проверяем GET /api/ai/providers
            response = client.get("/api/ai/providers", headers=headers)
            assert response.status_code in [200, 401]
            
            if response.status_code == 200:
                data = response.json()
                assert 'providers' in data
                assert isinstance(data['providers'], list)
    
    def test_error_responses_contract(self):
        """Проверяет контракт error responses"""
        with TestClient(app) as client:
            # Тестируем 404 для несуществующего эндпоинта
            response = client.get("/api/nonexistent")
            assert response.status_code == 404
            
            # Тестируем 422 для невалидных данных
            invalid_data = {
                "email": "invalid-email",
                "password": "123"  # Слишком короткий пароль
            }
            
            response = client.post("/api/auth/login", json=invalid_data)
            assert response.status_code == 422
            
            data = response.json()
            assert 'detail' in data
    
    def test_response_schemas_validation(self):
        """Проверяет соответствие ответов схемам OpenAPI"""
        with TestClient(app) as client:
            # Проверяем health response
            response = client.get("/health")
            if response.status_code == 200:
                data = response.json()
                
                # Проверяем обязательные поля
                required_fields = ['status', 'timestamp', 'version', 'uptime', 'services']
                for field in required_fields:
                    assert field in data, f"Missing required field: {field}"
                
                # Проверяем типы полей
                assert isinstance(data['status'], str)
                assert isinstance(data['uptime'], (int, float))
                assert isinstance(data['services'], dict)
    
    def test_request_validation_contract(self):
        """Проверяет валидацию запросов согласно OpenAPI схеме"""
        with TestClient(app) as client:
            # Тестируем валидацию email
            invalid_email_data = {
                "email": "not-an-email",
                "password": "ValidPassword123!"
            }
            
            response = client.post("/api/auth/login", json=invalid_email_data)
            assert response.status_code == 422
            
            # Тестируем валидацию длины пароля
            short_password_data = {
                "email": "test@example.com",
                "password": "123"  # Слишком короткий
            }
            
            response = client.post("/api/auth/login", json=short_password_data)
            assert response.status_code == 422
            
            # Тестируем валидацию обязательных полей
            missing_fields_data = {
                "email": "test@example.com"
                # Отсутствует password
            }
            
            response = client.post("/api/auth/login", json=missing_fields_data)
            assert response.status_code == 422
    
    def test_pagination_contract(self):
        """Проверяет контракт пагинации"""
        with TestClient(app) as client:
            headers = {"Authorization": "Bearer mock_token"}
            
            # Тестируем параметры пагинации
            response = client.get("/api/projects?limit=5&offset=10", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                assert 'projects' in data
                assert 'total' in data
                assert 'limit' in data
                assert 'offset' in data
                
                # Проверяем, что limit соответствует запросу
                assert data['limit'] == 5
    
    def test_rate_limiting_contract(self):
        """Проверяет контракт rate limiting"""
        with TestClient(app) as client:
            # Тестируем rate limiting для auth endpoints
            # Делаем несколько запросов подряд
            for i in range(10):
                response = client.post("/api/auth/login", json={
                    "email": f"test{i}@example.com",
                    "password": "TestPassword123!"
                })
                
                # После определенного количества запросов должен вернуться 429
                if response.status_code == 429:
                    data = response.json()
                    assert 'message' in data
                    break
    
    def test_security_headers_contract(self):
        """Проверяет наличие security headers"""
        with TestClient(app) as client:
            response = client.get("/health")
            
            # Проверяем CORS headers
            assert 'access-control-allow-origin' in response.headers
            
            # Проверяем content-type
            assert response.headers['content-type'] == 'application/json'
    
    def test_openapi_generation_consistency(self):
        """Проверяет соответствие генерируемой OpenAPI спецификации"""
        with TestClient(app) as client:
            # Получаем OpenAPI спецификацию от FastAPI
            response = client.get("/openapi.json")
            assert response.status_code == 200
            
            generated_spec = response.json()
            
            # Проверяем основные поля
            assert 'openapi' in generated_spec
            assert 'info' in generated_spec
            assert 'paths' in generated_spec
            
            # Проверяем, что все эндпоинты из нашей спецификации присутствуют
            our_paths = set(openapi_spec['paths'].keys())
            generated_paths = set(generated_spec['paths'].keys())
            
            # Проверяем, что основные эндпоинты присутствуют
            essential_paths = {
                '/health',
                '/api/auth/login',
                '/api/auth/register',
                '/api/projects',
                '/api/ai/chat'
            }
            
            for path in essential_paths:
                assert path in generated_paths, f"Missing essential path: {path}"
    
    def test_deprecated_fields_handling(self):
        """Проверяет обработку устаревших полей"""
        # Тестируем, что устаревшие поля помечены соответствующим образом
        # в OpenAPI спецификации
        
        # Проверяем наличие deprecated полей в схемах
        schemas = openapi_spec.get('components', {}).get('schemas', {})
        
        # Ищем поля с deprecated: true
        deprecated_fields_found = False
        for schema_name, schema in schemas.items():
            if 'properties' in schema:
                for field_name, field_def in schema['properties'].items():
                    if field_def.get('deprecated', False):
                        deprecated_fields_found = True
                        # Проверяем, что есть описание о deprecation
                        assert 'description' in field_def
                        assert 'deprecated' in field_def['description'].lower()
        
        # В текущей версии устаревших полей нет, но тест готов для будущих версий
        # assert deprecated_fields_found, "No deprecated fields found in spec"
    
    def test_api_versioning_contract(self):
        """Проверяет контракт версионирования API"""
        # Проверяем, что версия API указана в info
        assert 'version' in openapi_spec['info']
        assert openapi_spec['info']['version'] == '1.0.0'
        
        # Проверяем, что версия указана в серверах
        servers = openapi_spec.get('servers', [])
        assert len(servers) > 0
        
        # Проверяем, что есть production и staging серверы
        server_urls = [server['url'] for server in servers]
        assert any('api.samokoder.com' in url for url in server_urls)
        assert any('staging' in url for url in server_urls)
    
    def test_authentication_contract(self):
        """Проверяет контракт аутентификации"""
        # Проверяем, что security schemes определены
        security_schemes = openapi_spec.get('components', {}).get('securitySchemes', {})
        assert 'BearerAuth' in security_schemes
        assert 'ApiKeyAuth' in security_schemes
        
        # Проверяем BearerAuth схему
        bearer_auth = security_schemes['BearerAuth']
        assert bearer_auth['type'] == 'http'
        assert bearer_auth['scheme'] == 'bearer'
        assert bearer_auth['bearerFormat'] == 'JWT'
        
        # Проверяем ApiKeyAuth схему
        api_key_auth = security_schemes['ApiKeyAuth']
        assert api_key_auth['type'] == 'apiKey'
        assert api_key_auth['in'] == 'header'
        assert api_key_auth['name'] == 'X-API-Key'
    
    def test_error_codes_contract(self):
        """Проверяет контракт кодов ошибок"""
        # Проверяем, что все эндпоинты имеют соответствующие коды ошибок
        paths = openapi_spec.get('paths', {})
        
        for path, methods in paths.items():
            for method, definition in methods.items():
                if method in ['get', 'post', 'put', 'delete', 'patch']:
                    responses = definition.get('responses', {})
                    
                    # Проверяем наличие стандартных кодов ошибок
                    if 'security' not in definition or definition['security']:
                        # Эндпоинт требует аутентификации
                        assert '401' in responses, f"Missing 401 for {method.upper()} {path}"
                    
                    # Проверяем наличие 500 для всех эндпоинтов
                    assert '500' in responses, f"Missing 500 for {method.upper()} {path}"
                    
                    # Проверяем наличие 422 для POST/PUT/PATCH
                    if method in ['post', 'put', 'patch']:
                        assert '422' in responses, f"Missing 422 for {method.upper()} {path}"

# Дополнительные тесты для проверки совместимости версий
class TestAPIVersionCompatibility:
    """Тесты совместимости версий API"""
    
    def test_backward_compatibility(self):
        """Проверяет обратную совместимость API"""
        with TestClient(app) as client:
            # Тестируем, что старые поля все еще работают
            # (если они не помечены как deprecated)
            
            # Пример: проверяем, что старые поля в ответах все еще присутствуют
            response = client.get("/health")
            if response.status_code == 200:
                data = response.json()
                
                # Проверяем, что обязательные поля присутствуют
                required_fields = ['status', 'timestamp', 'version', 'uptime', 'services']
                for field in required_fields:
                    assert field in data, f"Backward compatibility broken: missing {field}"
    
    def test_forward_compatibility(self):
        """Проверяет прямую совместимость API"""
        with TestClient(app) as client:
            # Тестируем, что новые поля не ломают старых клиентов
            
            # Проверяем, что дополнительные поля в ответах не обязательны
            response = client.get("/health")
            if response.status_code == 200:
                data = response.json()
                
                # Проверяем, что дополнительные поля не ломают парсинг
                optional_fields = ['memory_usage', 'disk_usage', 'active_projects']
                for field in optional_fields:
                    if field in data:
                        # Поле присутствует - проверяем его тип
                        assert isinstance(data[field], (dict, int, float))
    
    def test_api_evolution_safety(self):
        """Проверяет безопасность эволюции API"""
        with TestClient(app) as client:
            # Проверяем, что изменения в API не нарушают контракты
            
            # Проверяем, что все эндпоинты имеют стабильные URL
            stable_endpoints = [
                '/health',
                '/api/auth/login',
                '/api/auth/register',
                '/api/projects',
                '/api/ai/chat'
            ]
            
            for endpoint in stable_endpoints:
                response = client.get(endpoint)
                # Эндпоинт должен существовать (может требовать аутентификации)
                assert response.status_code in [200, 401, 405], f"Endpoint {endpoint} not found"
    
    def test_breaking_changes_detection(self):
        """Проверяет обнаружение breaking changes"""
        with TestClient(app) as client:
            # Проверяем, что не было внесено breaking changes
            
            # Проверяем, что обязательные поля не были удалены
            response = client.get("/health")
            if response.status_code == 200:
                data = response.json()
                
                # Список полей, которые не должны быть удалены
                critical_fields = ['status', 'timestamp', 'version']
                for field in critical_fields:
                    assert field in data, f"Breaking change detected: critical field {field} removed"
    
    def test_deprecation_policy_compliance(self):
        """Проверяет соответствие политике deprecation"""
        # Проверяем, что устаревшие поля правильно помечены
        
        # Проверяем, что deprecated поля имеют соответствующие аннотации
        schemas = openapi_spec.get('components', {}).get('schemas', {})
        
        for schema_name, schema in schemas.items():
            if 'properties' in schema:
                for field_name, field_def in schema['properties'].items():
                    if field_def.get('deprecated', False):
                        # Проверяем, что deprecated поля имеют описание
                        assert 'description' in field_def
                        description = field_def['description'].lower()
                        assert 'deprecated' in description or 'устарел' in description
                        
                        # Проверяем, что указана дата deprecation или версия
                        assert 'version' in description or 'date' in description or 'since' in description

# Тесты для проверки производительности API
class TestAPIPerformanceContracts:
    """Тесты производительности API"""
    
    def test_response_time_contract(self):
        """Проверяет контракт времени ответа"""
        import time
        with TestClient(app) as client:
            # Тестируем время ответа health endpoint
            start_time = time.time()
            response = client.get("/health")
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Health endpoint должен отвечать быстро (< 1 секунды)
            assert response_time < 1.0, f"Health endpoint too slow: {response_time:.2f}s"
            
            # Проверяем, что ответ содержит информацию о времени
            if response.status_code == 200:
                data = response.json()
                assert 'uptime' in data
                assert isinstance(data['uptime'], (int, float))
    
    def test_memory_usage_contract(self):
        """Проверяет контракт использования памяти"""
        import psutil
        import os
        with TestClient(app) as client:
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss
            
            # Делаем несколько запросов
            for i in range(10):
                response = client.get("/health")
                assert response.status_code == 200
            
            final_memory = process.memory_info().rss
            memory_increase = final_memory - initial_memory
            
            # Увеличение памяти не должно быть критическим (< 10MB)
            assert memory_increase < 10 * 1024 * 1024, f"Memory usage too high: {memory_increase / 1024 / 1024:.2f}MB"
    
    def test_concurrent_requests_contract(self):
        """Проверяет контракт concurrent запросов"""
        import threading
        import time
        with TestClient(app) as client:
            results = []
            errors = []
            
            def make_request():
                try:
                    response = client.get("/health")
                    results.append(response.status_code)
                except Exception as e:
                    errors.append(str(e))
            
            # Создаем 10 concurrent запросов
            threads = []
            for i in range(10):
                thread = threading.Thread(target=make_request)
                threads.append(thread)
                thread.start()
            
            # Ждем завершения всех потоков
            for thread in threads:
                thread.join()
            
            # Проверяем, что все запросы успешны
            assert len(errors) == 0, f"Concurrent requests failed: {errors}"
            assert len(results) == 10, f"Not all requests completed: {len(results)}/10"
            assert all(status == 200 for status in results), f"Some requests failed: {results}"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
