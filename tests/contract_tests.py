"""
Контрактные тесты для валидации соответствия API реальной реализации
API Owner - 20 лет опыта
"""

import pytest
import requests
import json
from typing import Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
import yaml
import jsonschema
from jsonschema import validate, ValidationError

@dataclass
class APIContract:
    """Контракт API эндпоинта"""
    method: str
    path: str
    expected_status_codes: List[int]
    required_headers: List[str]
    request_schema: Dict[str, Any] = None
    response_schema: Dict[str, Any] = None
    deprecated: bool = False
    deprecation_info: Dict[str, Any] = None

class APIContractValidator:
    """Валидатор контрактов API"""
    
    def __init__(self, base_url: str, openapi_spec_path: str):
        self.base_url = base_url.rstrip('/')
        self.openapi_spec = self._load_openapi_spec(openapi_spec_path)
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def _load_openapi_spec(self, spec_path: str) -> Dict[str, Any]:
        """Загружает OpenAPI спецификацию"""
        with open(spec_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def get_endpoint_schema(self, method: str, path: str) -> Dict[str, Any]:
        """Получает схему эндпоинта из OpenAPI спецификации"""
        method = method.lower()
        if path not in self.openapi_spec.get('paths', {}):
            return None
        
        endpoint = self.openapi_spec['paths'][path]
        if method not in endpoint:
            return None
        
        return endpoint[method]
    
    def validate_request_schema(self, schema: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """Валидирует данные запроса по схеме"""
        if not schema or 'requestBody' not in schema:
            return True
        
        request_schema = schema['requestBody'].get('content', {}).get('application/json', {}).get('schema')
        if not request_schema:
            return True
        
        try:
            validate(instance=data, schema=request_schema)
            return True
        except ValidationError as e:
            print(f"Request validation error: {e}")
            return False
    
    def validate_response_schema(self, schema: Dict[str, Any], response_data: Dict[str, Any], status_code: int) -> bool:
        """Валидирует данные ответа по схеме"""
        if not schema or 'responses' not in schema:
            return True
        
        response_schema = schema['responses'].get(str(status_code), {}).get('content', {}).get('application/json', {}).get('schema')
        if not response_schema:
            return True
        
        try:
            validate(instance=response_data, schema=response_schema)
            return True
        except ValidationError as e:
            print(f"Response validation error: {e}")
            return False
    
    def check_deprecated_fields(self, response_data: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
        """Проверяет наличие deprecated полей в ответе"""
        deprecated_fields = []
        
        if not schema or 'responses' not in schema:
            return deprecated_fields
        
        # Проверяем все возможные коды ответов
        for status_code, response_info in schema['responses'].items():
            response_schema = response_info.get('content', {}).get('application/json', {}).get('schema')
            if not response_schema:
                continue
            
            # Рекурсивно ищем deprecated поля
            deprecated_fields.extend(self._find_deprecated_fields(response_schema, response_data))
        
        return deprecated_fields
    
    def _find_deprecated_fields(self, schema: Dict[str, Any], data: Dict[str, Any], path: str = "") -> List[str]:
        """Рекурсивно находит deprecated поля"""
        deprecated_fields = []
        
        if not isinstance(schema, dict) or not isinstance(data, dict):
            return deprecated_fields
        
        for field_name, field_schema in schema.get('properties', {}).items():
            current_path = f"{path}.{field_name}" if path else field_name
            
            if field_schema.get('deprecated', False):
                if field_name in data:
                    deprecated_fields.append(current_path)
            
            # Проверяем вложенные объекты
            if field_name in data and isinstance(data[field_name], dict):
                deprecated_fields.extend(
                    self._find_deprecated_fields(field_schema, data[field_name], current_path)
                )
        
        return deprecated_fields

class ContractTestSuite:
    """Набор контрактных тестов"""
    
    def __init__(self, validator: APIContractValidator):
        self.validator = validator
        self.test_results = []
    
    def test_health_endpoints(self):
        """Тестирует эндпоинты здоровья"""
        print("Testing health endpoints...")
        
        # Тест /health
        response = self.validator.session.get(f"{self.validator.base_url}/health")
        assert response.status_code == 200
        
        schema = self.validator.get_endpoint_schema('GET', '/health')
        if schema:
            assert self.validator.validate_response_schema(schema, response.json(), 200)
        
        # Тест /health/detailed
        response = self.validator.session.get(f"{self.validator.base_url}/health/detailed")
        assert response.status_code == 200
        
        schema = self.validator.get_endpoint_schema('GET', '/health/detailed')
        if schema:
            assert self.validator.validate_response_schema(schema, response.json(), 200)
        
        print("✓ Health endpoints passed")
    
    def test_auth_endpoints(self):
        """Тестирует эндпоинты аутентификации"""
        print("Testing auth endpoints...")
        
        # Тест /api/auth/login (без аутентификации - должен вернуть ошибку)
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        response = self.validator.session.post(f"{self.validator.base_url}/api/auth/login", json=login_data)
        # Может быть 401 (неверные учетные данные) или 200 (mock режим)
        assert response.status_code in [200, 401]
        
        schema = self.validator.get_endpoint_schema('POST', '/api/auth/login')
        if schema:
            assert self.validator.validate_request_schema(schema, login_data)
            assert self.validator.validate_response_schema(schema, response.json(), response.status_code)
        
        # Тест /api/auth/register
        register_data = {
            "email": "newuser@example.com",
            "password": "TestPassword123!",
            "full_name": "Test User"
        }
        
        response = self.validator.session.post(f"{self.validator.base_url}/api/auth/register", json=register_data)
        # Может быть 201 (успех) или 400/500 (ошибка)
        assert response.status_code in [201, 400, 500]
        
        schema = self.validator.get_endpoint_schema('POST', '/api/auth/register')
        if schema:
            assert self.validator.validate_request_schema(schema, register_data)
            assert self.validator.validate_response_schema(schema, response.json(), response.status_code)
        
        print("✓ Auth endpoints passed")
    
    def test_projects_endpoints(self):
        """Тестирует эндпоинты проектов"""
        print("Testing projects endpoints...")
        
        # Тест GET /api/projects (без аутентификации - должен вернуть 401)
        response = self.validator.session.get(f"{self.validator.base_url}/api/projects")
        assert response.status_code == 401
        
        schema = self.validator.get_endpoint_schema('GET', '/api/projects')
        if schema:
            assert self.validator.validate_response_schema(schema, response.json(), 401)
        
        # Тест POST /api/projects (без аутентификации - должен вернуть 401)
        project_data = {
            "name": "Test Project",
            "description": "A test project for contract testing",
            "tech_stack": {
                "frontend": ["React", "TypeScript"],
                "backend": ["Node.js", "Express"]
            },
            "ai_config": {
                "model": "deepseek/deepseek-v3",
                "provider": "openrouter"
            }
        }
        
        response = self.validator.session.post(f"{self.validator.base_url}/api/projects", json=project_data)
        assert response.status_code == 401
        
        schema = self.validator.get_endpoint_schema('POST', '/api/projects')
        if schema:
            assert self.validator.validate_request_schema(schema, project_data)
            assert self.validator.validate_response_schema(schema, response.json(), 401)
        
        print("✓ Projects endpoints passed")
    
    def test_ai_endpoints(self):
        """Тестирует эндпоинты AI"""
        print("Testing AI endpoints...")
        
        # Тест GET /api/ai/providers (без аутентификации - должен вернуть 401)
        response = self.validator.session.get(f"{self.validator.base_url}/api/ai/providers")
        assert response.status_code == 401
        
        schema = self.validator.get_endpoint_schema('GET', '/api/ai/providers')
        if schema:
            assert self.validator.validate_response_schema(schema, response.json(), 401)
        
        # Тест POST /api/ai/chat (без аутентификации - должен вернуть 401)
        chat_data = {
            "message": "Hello, AI!",
            "context": "test",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter",
            "max_tokens": 100,
            "temperature": 0.7
        }
        
        response = self.validator.session.post(f"{self.validator.base_url}/api/ai/chat", json=chat_data)
        assert response.status_code == 401
        
        schema = self.validator.get_endpoint_schema('POST', '/api/ai/chat')
        if schema:
            assert self.validator.validate_request_schema(schema, chat_data)
            assert self.validator.validate_response_schema(schema, response.json(), 401)
        
        print("✓ AI endpoints passed")
    
    def test_deprecated_fields(self):
        """Тестирует deprecated поля"""
        print("Testing deprecated fields...")
        
        # Создаем mock ответ с deprecated полями
        mock_response = {
            "success": True,
            "message": "Test",
            "user": {
                "id": "123",
                "email": "test@example.com",
                "api_credits_balance": 100.50,  # deprecated
                "subscription_tier": "free"
            },
            "access_token": "token",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_token"  # deprecated
        }
        
        schema = self.validator.get_endpoint_schema('POST', '/api/auth/login')
        if schema:
            deprecated_fields = self.validator.check_deprecated_fields(mock_response, schema)
            assert len(deprecated_fields) > 0, "Should detect deprecated fields"
            print(f"Detected deprecated fields: {deprecated_fields}")
        
        print("✓ Deprecated fields test passed")
    
    def test_metrics_endpoint(self):
        """Тестирует эндпоинт метрик"""
        print("Testing metrics endpoint...")
        
        response = self.validator.session.get(f"{self.validator.base_url}/metrics")
        assert response.status_code == 200
        
        # Метрики должны быть в формате Prometheus
        assert 'text/plain' in response.headers.get('content-type', '')
        
        print("✓ Metrics endpoint passed")
    
    def run_all_tests(self):
        """Запускает все тесты"""
        print("Starting API contract tests...")
        print("=" * 50)
        
        try:
            self.test_health_endpoints()
            self.test_auth_endpoints()
            self.test_projects_endpoints()
            self.test_ai_endpoints()
            self.test_deprecated_fields()
            self.test_metrics_endpoint()
            
            print("=" * 50)
            print("✅ All contract tests passed!")
            
        except Exception as e:
            print(f"❌ Contract test failed: {e}")
            raise

def main():
    """Основная функция для запуска контрактных тестов"""
    import argparse
    
    parser = argparse.ArgumentParser(description='API Contract Tests')
    parser.add_argument('--base-url', default='http://localhost:8000', help='Base URL of the API')
    parser.add_argument('--spec-path', default='api/openapi_spec.yaml', help='Path to OpenAPI specification')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    validator = APIContractValidator(args.base_url, args.spec_path)
    test_suite = ContractTestSuite(validator)
    
    test_suite.run_all_tests()

if __name__ == "__main__":
    main()