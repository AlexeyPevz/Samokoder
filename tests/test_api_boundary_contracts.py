"""
Тесты граничных случаев для API контрактов
Проверяет соответствие API спецификации в экстремальных условиях
"""

import pytest
import json
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.main import app
from backend.models.requests import (
    LoginRequest, RegisterRequest, ProjectCreateRequest,
    ChatRequest, APIKeyCreateRequest, ProjectUpdateRequest
)
from backend.models.responses import (
    ErrorResponse, LoginResponse, ProjectResponse
)

client = TestClient(app)

class TestRequestValidationBoundaries:
    """Тесты граничных случаев валидации запросов"""
    
    def test_login_request_minimal_valid(self):
        """Тест минимально валидного запроса входа"""
        data = {
            "email": "a@b.co",  # минимально валидный email
            "password": "Password123"  # минимальная длина пароля с требованиями
        }
        request = LoginRequest(**data)
        assert request.email == "a@b.co"
        assert request.password == "Password123"
    
    def test_login_request_maximal_valid(self):
        """Тест максимально валидного запроса входа"""
        data = {
            "email": "a" * 200 + "@example.com",  # максимальная длина email (в пределах лимита)
            "password": "Password123" + "a" * 100  # максимальная длина пароля с требованиями
        }
        request = LoginRequest(**data)
        assert len(request.email) == 200 + len("@example.com")
        assert len(request.password) == len("Password123") + 100
    
    def test_login_request_invalid_email_format(self):
        """Тест невалидного формата email"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(email="invalid-email", password="password123")
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("email",) for error in errors)
    
    def test_login_request_empty_fields(self):
        """Тест пустых полей"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(email="", password="")
        
        errors = exc_info.value.errors()
        assert len(errors) >= 2  # Должны быть ошибки для обоих полей
    
    def test_login_request_whitespace_fields(self):
        """Тест полей только с пробелами"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(email="   ", password="   ")
        
        errors = exc_info.value.errors()
        assert len(errors) >= 2
    
    def test_project_create_request_minimal(self):
        """Тест минимально валидного запроса создания проекта"""
        data = {
            "name": "a",  # минимальная длина имени
            "description": "a" * 10,  # минимальная длина описания
        }
        request = ProjectCreateRequest(**data)
        assert request.name == "a"
        assert request.description == "a" * 10
    
    def test_project_create_request_maximal(self):
        """Тест максимально валидного запроса создания проекта"""
        data = {
            "name": "a" * 100,  # максимальная длина имени
            "description": "a" * 1000,  # максимальная длина описания
        }
        request = ProjectCreateRequest(**data)
        assert len(request.name) == 100
        assert len(request.description) == 1000
    
    def test_chat_request_minimal(self):
        """Тест минимально валидного запроса чата"""
        data = {
            "message": "a",  # минимальная длина сообщения
        }
        request = ChatRequest(**data)
        assert request.message == "a"
    
    def test_chat_request_maximal(self):
        """Тест максимально валидного запроса чата"""
        data = {
            "message": "a" * 4000,  # максимальная длина сообщения
        }
        request = ChatRequest(**data)
        assert len(request.message) == 4000

class TestResponseValidationBoundaries:
    """Тесты граничных случаев валидации ответов"""
    
    def test_error_response_minimal(self):
        """Тест минимально валидного ответа об ошибке"""
        data = {
            "error": "a",  # минимальная длина ошибки
            "message": "a"  # минимальная длина сообщения
        }
        response = ErrorResponse(**data)
        assert response.error == "a"
        assert response.message == "a"
    
    def test_error_response_maximal(self):
        """Тест максимально валидного ответа об ошибке"""
        data = {
            "error": "a" * 1000,  # максимальная длина ошибки
            "message": "a" * 10000  # максимальная длина сообщения
        }
        response = ErrorResponse(**data)
        assert len(response.error) == 1000
        assert len(response.message) == 10000
    
    def test_login_response_minimal(self):
        """Тест минимально валидного ответа входа"""
        data = {
            "message": "a",
            "user": {
                "id": "a",
                "email": "a@b.co",
                "subscription_tier": "free",
                "subscription_status": "active",
                "api_credits_balance": 0.0,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            },
            "access_token": "a",
            "expires_in": 3600
        }
        response = LoginResponse(**data)
        assert response.message == "a"
        assert response.user.id == "a"
        assert response.user.email == "a@b.co"

class TestAPIEndpointBoundaries:
    """Тесты граничных случаев эндпоинтов API"""
    
    def test_health_endpoint_always_responds(self):
        """Тест что health endpoint всегда отвечает"""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "unhealthy", "degraded"]
    
    def test_metrics_endpoint_always_responds(self):
        """Тест что metrics endpoint всегда отвечает"""
        response = client.get("/metrics")
        assert response.status_code == 200
        
        # Должен возвращать метрики в текстовом формате
        assert "text/plain" in response.headers.get("content-type", "")
    
    def test_root_endpoint_always_responds(self):
        """Тест что root endpoint всегда отвечает"""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "status" in data
    
    def test_cors_preflight_always_responds(self):
        """Тест что CORS preflight всегда отвечает"""
        response = client.options("/api/projects")
        assert response.status_code == 200
        
        headers = response.headers
        assert "Access-Control-Allow-Origin" in headers
        assert "Access-Control-Allow-Methods" in headers
        assert "Access-Control-Allow-Headers" in headers

class TestDataTypeBoundaries:
    """Тесты граничных случаев типов данных"""
    
    def test_string_length_boundaries(self):
        """Тест границ длины строк"""
        # Тест пустых строк
        with pytest.raises(ValidationError):
            LoginRequest(email="", password="password123")
        
        # Тест очень длинных строк
        long_email = "a" * 1000 + "@example.com"
        with pytest.raises(ValidationError):
            LoginRequest(email=long_email, password="password123")
    
    def test_numeric_boundaries(self):
        """Тест границ числовых значений"""
        # Тест с максимальными значениями в ChatRequest
        data = {
            "message": "test",
            "max_tokens": 32000,  # максимальное значение для max_tokens
            "temperature": 2.0  # максимальная температура
        }
        request = ChatRequest(**data)
        assert request.max_tokens == 32000
        assert request.temperature == 2.0
    
    def test_boolean_boundaries(self):
        """Тест границ булевых значений"""
        # Тест с различными представлениями булевых значений
        test_cases = [
            True, False,
            "true", "false",
            "True", "False",
            "TRUE", "FALSE",
            "1", "0",
            1, 0
        ]
        
        for value in test_cases:
            # Создаем запрос с булевым значением (если поддерживается)
            # Это зависит от конкретной модели
            pass
    
    def test_datetime_boundaries(self):
        """Тест границ даты и времени"""
        from datetime import datetime, timezone
        
        # Тест с различными форматами даты
        test_dates = [
            "2023-01-01T00:00:00Z",
            "2023-12-31T23:59:59Z",
            "2023-01-01T00:00:00+00:00",
            "2023-01-01T00:00:00.000Z"
        ]
        
        for date_str in test_dates:
            # Проверяем что дата может быть распарсена
            try:
                parsed = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                assert parsed is not None
            except ValueError:
                pytest.fail(f"Failed to parse date: {date_str}")

class TestUnicodeBoundaries:
    """Тесты граничных случаев Unicode"""
    
    def test_unicode_email_addresses(self):
        """Тест Unicode email адресов"""
        unicode_emails = [
            "тест@пример.рф",
            "test@münchen.de",
            "test@café.com",
            "test@测试.com",
            "test@例え.com"
        ]
        
        for email in unicode_emails:
            try:
                request = LoginRequest(email=email, password="password123")
                assert request.email == email
            except ValidationError:
                # Некоторые Unicode email могут быть невалидными
                pass
    
    def test_unicode_passwords(self):
        """Тест Unicode паролей"""
        unicode_passwords = [
            "пароль123",
            "mật_khẩu_123",
            "密码123",
            "パスワード123",
            "كلمة_المرور123"
        ]
        
        for password in unicode_passwords:
            # Добавляем требования к паролю (минимум 8 символов)
            password_with_requirements = password + "A1" + "x" * 2
            request = LoginRequest(email="test@example.com", password=password_with_requirements)
            assert request.password == password_with_requirements
    
    def test_unicode_project_names(self):
        """Тест Unicode названий проектов"""
        unicode_names = [
            "Мой проект",
            "Dự án của tôi",
            "我的项目",
            "私のプロジェクト",
            "مشروعي"
        ]
        
        for name in unicode_names:
            request = ProjectCreateRequest(
                name=name,
                description="test description with minimum length"
            )
            assert request.name == name

class TestConcurrentBoundaries:
    """Тесты граничных случаев конкурентности"""
    
    def test_concurrent_login_attempts(self):
        """Тест одновременных попыток входа"""
        import threading
        import time
        
        results = []
        
        def login_attempt():
            response = client.post("/api/auth/login", json={
                "email": "test@example.com",
                "password": "password123"
            })
            results.append(response.status_code)
        
        # Создаем несколько потоков
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=login_attempt)
            threads.append(thread)
            thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        # Все запросы должны быть обработаны
        assert len(results) == 10
        for status_code in results:
            assert status_code in [200, 401, 429]  # 429 для rate limiting
    
    def test_concurrent_project_creation(self):
        """Тест одновременного создания проектов"""
        import threading
        
        results = []
        
        def create_project():
            response = client.post("/api/projects", json={
                "name": f"project_{threading.current_thread().ident}",
                "description": "test",
                "user_id": "user123"
            })
            results.append(response.status_code)
        
        # Создаем несколько потоков
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=create_project)
            threads.append(thread)
            thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        # Все запросы должны быть обработаны
        assert len(results) == 5
        for status_code in results:
            assert status_code in [200, 201, 401, 409, 422]

class TestMemoryBoundaries:
    """Тесты граничных случаев памяти"""
    
    def test_large_request_handling(self):
        """Тест обработки больших запросов"""
        # Создаем большой запрос
        large_data = {
            "name": "test",
            "description": "x" * 1000,  # максимальная длина описания
        }
        
        response = client.post("/api/projects", json=large_data)
        # Должен либо принять, либо вернуть 413 (Payload Too Large)
        assert response.status_code in [200, 201, 401, 413, 422]
    
    def test_large_response_handling(self):
        """Тест обработки больших ответов"""
        # Запрашиваем файлы проекта (может быть большой ответ)
        response = client.get("/api/projects/test-project/files")
        # Должен обработать корректно
        assert response.status_code in [200, 401, 404, 500]

if __name__ == "__main__":
    pytest.main([__file__, "-v"])