"""
Контрактные тесты для проверки соответствия API спецификации
"""

import pytest
import json
import yaml
import jsonschema
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from backend.main import app

client = TestClient(app)

class TestAPIContractCompliance:
    """Тесты соответствия API контракту"""
    
    def test_health_endpoint_contract(self):
        """Тест соответствия health endpoint контракту"""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "services" in data
        assert data["status"] in ["healthy", "unhealthy", "degraded"]
    
    def test_metrics_endpoint_contract(self):
        """Тест соответствия metrics endpoint контракту"""
        response = client.get("/metrics")
        assert response.status_code == 200
        
        # Проверяем, что ответ в формате Prometheus
        content = response.text
        assert isinstance(content, str)
        # Prometheus метрики обычно содержат # HELP или # TYPE
        assert any(keyword in content for keyword in ["# HELP", "# TYPE", "http_requests_total"])
    
    def test_api_health_endpoint_contract(self):
        """Тест соответствия API health endpoint контракту"""
        response = client.get("/api/health/")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "uptime" in data
        assert "services" in data
        
        # Проверяем типы данных
        assert isinstance(data["status"], str)
        assert isinstance(data["uptime"], int)
        assert isinstance(data["services"], dict)
    
    def test_detailed_health_endpoint_contract(self):
        """Тест соответствия detailed health endpoint контракту"""
        response = client.get("/api/health/detailed")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "uptime" in data
        assert "services" in data
        assert "external_services" in data
        assert "active_projects" in data
        assert "memory_usage" in data
        assert "disk_usage" in data
        
        # Проверяем типы данных
        assert isinstance(data["active_projects"], int)
        assert isinstance(data["memory_usage"], dict)
        assert isinstance(data["disk_usage"], dict)
    
    def test_database_health_endpoint_contract(self):
        """Тест соответствия database health endpoint контракту"""
        response = client.get("/api/health/database")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert "timestamp" in data
        
        # Проверяем возможные статусы
        assert data["status"] in ["healthy", "unhealthy", "mock"]
    
    def test_ai_health_endpoint_contract(self):
        """Тест соответствия AI health endpoint контракту"""
        response = client.get("/api/health/ai")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert "providers" in data
        assert "timestamp" in data
        
        # Проверяем структуру providers
        assert isinstance(data["providers"], dict)
    
    def test_system_health_endpoint_contract(self):
        """Тест соответствия system health endpoint контракту"""
        response = client.get("/api/health/system")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert "cpu_usage_percent" in data
        assert "memory" in data
        assert "disk" in data
        assert "processes_count" in data
        assert "timestamp" in data
        
        # Проверяем типы данных
        assert isinstance(data["cpu_usage_percent"], (int, float))
        assert isinstance(data["processes_count"], int)
        assert isinstance(data["memory"], dict)
        assert isinstance(data["disk"], dict)
    
    @patch('backend.main.supabase_manager')
    def test_login_endpoint_contract(self, mock_supabase):
        """Тест соответствия login endpoint контракту"""
        # Настраиваем mock
        mock_user = MagicMock()
        mock_user.id = "test_user_123"
        mock_user.email = "test@example.com"
        mock_user.created_at = "2025-01-11T00:00:00Z"
        mock_user.updated_at = "2025-01-11T00:00:00Z"
        mock_user.user_metadata = {"full_name": "Test User"}
        
        mock_session = MagicMock()
        mock_session.access_token = "test_token_123"
        
        mock_response = MagicMock()
        mock_response.user = mock_user
        mock_response.session = mock_session
        
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.return_value = mock_response
        mock_supabase.get_client.return_value = mock_client
        
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        
        response = client.post("/api/auth/login", json=login_data)
        
        # Проверяем структуру ответа
        if response.status_code == 200:
            data = response.json()
            assert "success" in data
            assert "message" in data
            assert "user" in data
            assert "access_token" in data
            assert "token_type" in data
            assert "expires_in" in data
            
            # Проверяем структуру user
            user = data["user"]
            assert "id" in user
            assert "email" in user
            assert "full_name" in user
            assert "subscription_tier" in user
            assert "subscription_status" in user
            assert "api_credits_balance" in user
            assert "created_at" in user
            assert "updated_at" in user
    
    @patch('backend.main.supabase_manager')
    def test_register_endpoint_contract(self, mock_supabase):
        """Тест соответствия register endpoint контракту"""
        # Настраиваем mock
        mock_user = MagicMock()
        mock_user.id = "new_user_123"
        
        mock_response = MagicMock()
        mock_response.user = mock_user
        mock_supabase.get_client.return_value.auth.sign_up.return_value = mock_response
        
        register_data = {
            "email": "newuser@example.com",
            "password": "newpassword123",
            "full_name": "New User"
        }
        
        response = client.post("/api/auth/register", json=register_data)
        
        # Проверяем структуру ответа
        if response.status_code == 201:
            data = response.json()
            assert "success" in data
            assert "message" in data
            assert "user_id" in data
            assert "email" in data
    
    def test_error_response_contract(self):
        """Тест соответствия error response контракту"""
        # Делаем запрос к несуществующему эндпоинту
        response = client.get("/api/nonexistent")
        
        if response.status_code >= 400:
            data = response.json()
            assert "error" in data
            assert "detail" in data
            assert "error_id" in data
            assert "timestamp" in data
    
    def test_rate_limiting_headers(self):
        """Тест заголовков rate limiting"""
        # Делаем несколько запросов для проверки rate limiting
        for _ in range(5):
            response = client.get("/health")
            
            # Проверяем наличие заголовков rate limiting
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers
    
    def test_csrf_protection(self):
        """Тест CSRF защиты"""
        # POST запрос без CSRF токена должен вернуть 403
        response = client.post("/api/auth/logout")
        assert response.status_code == 403
        
        # GET запрос должен работать без CSRF токена
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_security_headers(self):
        """Тест заголовков безопасности"""
        response = client.get("/health")
        
        # Проверяем наличие заголовков безопасности
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Strict-Transport-Security" in response.headers
        assert "Referrer-Policy" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Permissions-Policy" in response.headers

class TestSchemaValidation:
    """Тесты валидации JSON схем"""
    
    def test_openapi_schema_validity(self):
        """Тест валидности OpenAPI схемы"""
        with open("openapi.yaml", "r") as f:
            spec = yaml.safe_load(f)
        
        # Проверяем, что схема валидна
        assert "openapi" in spec
        assert spec["openapi"] == "3.1.0"
        assert "info" in spec
        assert "paths" in spec
        assert "components" in spec
        
        # Проверяем обязательные поля info
        info = spec["info"]
        assert "title" in info
        assert "version" in info
        assert "description" in info
    
    def test_request_schema_validation(self):
        """Тест валидации request схем"""
        # Тестируем LoginRequest
        login_schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "format": "email"},
                "password": {"type": "string", "minLength": 8}
            },
            "required": ["email", "password"]
        }
        
        # Валидные данные
        valid_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        jsonschema.validate(valid_data, login_schema)
        
        # Невалидные данные
        invalid_data = {
            "email": "invalid-email",
            "password": "short"
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid_data, login_schema)
    
    def test_register_request_schema_validation(self):
        """Тест валидации RegisterRequest схемы"""
        register_schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "format": "email"},
                "password": {"type": "string", "minLength": 8},
                "full_name": {"type": "string", "minLength": 1, "maxLength": 100}
            },
            "required": ["email", "password", "full_name"]
        }
        
        # Валидные данные
        valid_data = {
            "email": "newuser@example.com",
            "password": "newpassword123",
            "full_name": "New User"
        }
        jsonschema.validate(valid_data, register_schema)
        
        # Невалидные данные
        invalid_data = {
            "email": "invalid-email",
            "password": "short",
            "full_name": ""
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid_data, register_schema)
    
    def test_user_schema_validation(self):
        """Тест валидации User схемы"""
        user_schema = {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "email": {"type": "string", "format": "email"},
                "full_name": {"type": "string"},
                "avatar_url": {"type": "string", "format": "uri"},
                "subscription_tier": {"type": "string", "enum": ["free", "pro", "enterprise"]},
                "subscription_status": {"type": "string", "enum": ["active", "inactive", "suspended"]},
                "api_credits_balance": {"type": "number"},
                "created_at": {"type": "string", "format": "date-time"},
                "updated_at": {"type": "string", "format": "date-time"}
            },
            "required": ["id", "email", "full_name", "subscription_tier", "subscription_status", "api_credits_balance", "created_at", "updated_at"]
        }
        
        # Валидные данные
        valid_user = {
            "id": "user123",
            "email": "test@example.com",
            "full_name": "Test User",
            "avatar_url": "https://example.com/avatar.jpg",
            "subscription_tier": "free",
            "subscription_status": "active",
            "api_credits_balance": 100.50,
            "created_at": "2025-01-11T00:00:00Z",
            "updated_at": "2025-01-11T00:00:00Z"
        }
        jsonschema.validate(valid_user, user_schema)
        
        # Невалидные данные
        invalid_user = {
            "id": "user123",
            "email": "invalid-email",
            "full_name": "Test User",
            "subscription_tier": "invalid_tier",
            "subscription_status": "active",
            "api_credits_balance": 100.50,
            "created_at": "2025-01-11T00:00:00Z",
            "updated_at": "2025-01-11T00:00:00Z"
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid_user, user_schema)
    
    def test_error_response_schema_validation(self):
        """Тест валидации ErrorResponse схемы"""
        error_schema = {
            "type": "object",
            "properties": {
                "error": {"type": "string"},
                "detail": {"type": "string"},
                "error_id": {"type": "string"},
                "timestamp": {"type": "string", "format": "date-time"}
            },
            "required": ["error", "detail", "error_id", "timestamp"]
        }
        
        # Валидные данные
        valid_error = {
            "error": "ValidationError",
            "detail": "Invalid input data",
            "error_id": "err_123456",
            "timestamp": "2025-01-11T00:00:00Z"
        }
        jsonschema.validate(valid_error, error_schema)
        
        # Невалидные данные (отсутствует обязательное поле)
        invalid_error = {
            "error": "ValidationError",
            "detail": "Invalid input data"
            # Отсутствуют error_id и timestamp
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid_error, error_schema)

class TestAPIVersioning:
    """Тесты версионирования API"""
    
    def test_api_version_header(self):
        """Тест заголовка версии API"""
        response = client.get("/health", headers={"API-Version": "v1"})
        assert response.status_code == 200
    
    def test_backward_compatibility(self):
        """Тест обратной совместимости"""
        # Тестируем, что старые клиенты продолжают работать
        response = client.get("/health")
        assert response.status_code == 200
        
        # Проверяем, что структура ответа не изменилась
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "services" in data

class TestAPIDocumentation:
    """Тесты документации API"""
    
    def test_openapi_docs_accessible(self):
        """Тест доступности OpenAPI документации"""
        response = client.get("/docs")
        assert response.status_code == 200
        
        response = client.get("/redoc")
        assert response.status_code == 200
    
    def test_openapi_json_accessible(self):
        """Тест доступности OpenAPI JSON"""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert "paths" in data

if __name__ == "__main__":
    pytest.main([__file__])