"""
Security Tests
Тесты для проверки исправлений безопасности
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from backend.main import app
from backend.auth.dependencies import get_current_user, validate_jwt_token

client = TestClient(app)

class TestAuthenticationSecurity:
    """Тесты безопасности аутентификации"""
    
    def test_invalid_jwt_token_rejected(self):
        """Тест: невалидные JWT токены отклоняются"""
        response = client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "password123"},
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
    
    def test_expired_jwt_token_rejected(self):
        """Тест: истекшие JWT токены отклоняются"""
        # Создаем истекший токен
        expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MDAwMDAwMDB9.invalid"
        
        response = client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "password123"},
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401
    
    def test_rate_limiting_works(self):
        """Тест: rate limiting работает"""
        # Делаем много запросов подряд
        for i in range(10):
            response = client.post(
                "/api/auth/login",
                json={"email": f"test{i}@example.com", "password": "password123"}
            )
            if i >= 3:  # После 3 попыток должен сработать rate limiting
                assert response.status_code == 429
    
    def test_password_validation(self):
        """Тест: валидация пароля работает"""
        weak_passwords = [
            "123",  # Слишком короткий
            "password",  # Нет цифр и спецсимволов
            "12345678",  # Только цифры
            "Password",  # Нет цифр и спецсимволов
        ]
        
        for password in weak_passwords:
            response = client.post(
                "/api/auth/register",
                json={
                    "email": "test@example.com",
                    "password": password,
                    "full_name": "Test User"
                }
            )
            assert response.status_code == 400
    
    def test_csrf_protection(self):
        """Тест: CSRF защита работает"""
        response = client.post(
            "/api/projects",
            json={"name": "Test Project", "description": "Test Description"},
            headers={"Authorization": "Bearer valid_token"}
            # Нет X-CSRF-Token заголовка
        )
        assert response.status_code == 403
    
    def test_sensitive_data_not_logged(self):
        """Тест: чувствительные данные не попадают в логи"""
        with patch('backend.auth.dependencies.logger') as mock_logger:
            response = client.post(
                "/api/auth/login",
                json={"email": "test@example.com", "password": "secretpassword123"}
            )
            
            # Проверяем, что пароль не попал в логи
            for call in mock_logger.warning.call_args_list:
                assert "secretpassword123" not in str(call)
                assert "password" not in str(call)

class TestInputValidation:
    """Тесты валидации входных данных"""
    
    def test_sql_injection_prevention(self):
        """Тест: защита от SQL инъекций"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT * FROM users",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --"
        ]
        
        for malicious_input in malicious_inputs:
            response = client.post(
                "/api/ai/chat",
                json={"message": malicious_input},
                headers={"Authorization": "Bearer valid_token"}
            )
            # Должен быть отклонен или санитизирован
            assert response.status_code in [400, 422]
    
    def test_xss_prevention(self):
        """Тест: защита от XSS"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "vbscript:alert('xss')"
        ]
        
        for payload in xss_payloads:
            response = client.post(
                "/api/ai/chat",
                json={"message": payload},
                headers={"Authorization": "Bearer valid_token"}
            )
            # Должен быть отклонен или санитизирован
            assert response.status_code in [400, 422]
    
    def test_path_traversal_prevention(self):
        """Тест: защита от path traversal"""
        malicious_paths = [
            "../../../etc/passwd",
            "..\..\..\windows\system32\config\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for path in malicious_paths:
            response = client.get(
                f"/api/projects/test/files/{path}",
                headers={"Authorization": "Bearer valid_token"}
            )
            assert response.status_code == 400

class TestCORSecurity:
    """Тесты CORS безопасности"""
    
    def test_cors_restricts_origins(self):
        """Тест: CORS ограничивает домены"""
        response = client.options(
            "/api/projects",
            headers={
                "Origin": "https://malicious-site.com",
                "Access-Control-Request-Method": "POST"
            }
        )
        # Должен быть отклонен
        assert "https://malicious-site.com" not in response.headers.get("Access-Control-Allow-Origin", "")
    
    def test_cors_allows_trusted_origins(self):
        """Тест: CORS разрешает доверенные домены"""
        response = client.options(
            "/api/projects",
            headers={
                "Origin": "https://samokoder.com",
                "Access-Control-Request-Method": "POST"
            }
        )
        assert response.status_code == 200

if __name__ == "__main__":
    pytest.main([__file__])
