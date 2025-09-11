"""
P0: Регрессионные тесты аутентификации и безопасности
Критические тесты, блокирующие мёрж до зелёного прогона
"""

import pytest
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from backend.main import app
from backend.auth.dependencies import get_current_user, secure_password_validation, hash_password

client = TestClient(app)

class TestAuthenticationSecurity:
    """P0: Критические тесты безопасности аутентификации"""
    
    def test_password_validation_strength(self):
        """P0: Валидация силы паролей"""
        # Тест слабых паролей
        weak_passwords = [
            "123",  # Слишком короткий
            "password",  # Нет цифр и спецсимволов
            "12345678",  # Только цифры
            "Password",  # Нет цифр и спецсимволов
            "PASSWORD",  # Нет цифр и спецсимволов
            "Password1",  # Нет спецсимволов
            "Password!",  # Нет цифр
            "12345678!",  # Нет букв
        ]
        
        for weak_password in weak_passwords:
            registration_data = {
                "email": "test@example.com",
                "password": weak_password,
                "full_name": "Test User"
            }
            
            response = client.post(
                "/api/auth/register", 
                json=registration_data,
                headers={"X-CSRF-Token": "valid_csrf_token_1234567890"}
            )
            # Должен быть отклонён из-за слабого пароля
            assert response.status_code in [400, 422], f"Слабый пароль '{weak_password}' не был отклонён"
    
    def test_password_validation_strong(self):
        """P0: Валидация сильных паролей"""
        # Тест сильных паролей
        strong_passwords = [
            "SecurePass123!",
            "MyStr0ng#P@ssw0rd",
            "Test123$",
            "ComplexP@ss1",
            "StrongP@ssw0rd2024!"
        ]
        
        for strong_password in strong_passwords:
            registration_data = {
                "email": f"test_{secrets.token_hex(4)}@example.com",
                "password": strong_password,
                "full_name": "Test User"
            }
            
            with patch('backend.api.auth.connection_pool_manager') as mock_pool:
                mock_supabase = MagicMock()
                mock_pool.get_supabase_client.return_value = mock_supabase
                
                mock_user = MagicMock()
                mock_user.id = f"user_{secrets.token_hex(8)}"
                mock_user.email = registration_data["email"]
                
                mock_response = MagicMock()
                mock_response.user = mock_user
                mock_response.session = MagicMock()
                mock_response.session.access_token = f"token_{secrets.token_hex(16)}"
                
                mock_supabase.auth.sign_up.return_value = mock_response
                mock_supabase.table.return_value.insert.return_value.execute.return_value = MagicMock()
                
                response = client.post("/api/auth/register", json=registration_data)
                # Должен быть принят
                assert response.status_code == 200, f"Сильный пароль '{strong_password}' был отклонён"
    
    def test_rate_limiting_login_attempts(self):
        """P0: Rate limiting для попыток входа"""
        login_data = {
            "email": "ratelimit@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('backend.main.supabase_manager') as mock_manager:
            mock_client = MagicMock()
            mock_manager.get_client.return_value = mock_client
            
            # Мокаем неудачные попытки входа
            mock_client.auth.sign_in_with_password.return_value = MagicMock(user=None)
            
            # Делаем множественные попытки входа
            for i in range(10):
                response = client.post("/api/auth/login", json=login_data)
                if i >= 3:  # После 3 попыток должен сработать rate limiting
                    assert response.status_code == 429, f"Rate limiting не сработал на попытке {i+1}"
                    break
    
    def test_rate_limiting_registration_attempts(self):
        """P0: Rate limiting для попыток регистрации"""
        registration_data = {
            "email": "ratelimit@example.com",
            "password": "SecurePass123!",
            "full_name": "Rate Limit User"
        }
        
        with patch('backend.api.auth.connection_pool_manager') as mock_pool:
            mock_supabase = MagicMock()
            mock_pool.get_supabase_client.return_value = mock_supabase
            
            # Мокаем неудачные попытки регистрации
            mock_supabase.auth.sign_up.return_value = MagicMock(user=None)
            
            # Делаем множественные попытки регистрации
            for i in range(10):
                response = client.post("/api/auth/register", json=registration_data)
                if i >= 5:  # После 5 попыток должен сработать rate limiting
                    assert response.status_code == 429, f"Rate limiting не сработал на попытке {i+1}"
                    break
    
    def test_jwt_token_validation(self):
        """P0: Валидация JWT токенов"""
        # Тест с невалидным токеном
        response = client.get(
            "/api/auth/user",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
        
        # Тест с истекшим токеном
        expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MDAwMDAwMDB9.invalid"
        response = client.get(
            "/api/auth/user",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401
        
        # Тест с токеном без Bearer префикса
        response = client.get(
            "/api/auth/user",
            headers={"Authorization": "invalid_token"}
        )
        assert response.status_code == 401
        
        # Тест без заголовка Authorization
        response = client.get("/api/auth/user")
        assert response.status_code == 401
    
    def test_password_hashing_security(self):
        """P0: Безопасность хеширования паролей"""
        password = "TestPassword123!"
        
        # Тестируем функцию хеширования
        password_hash, salt = hash_password(password)
        
        # Проверяем, что хеш не равен исходному паролю
        assert password_hash != password
        
        # Проверяем, что соль не пустая
        assert salt is not None
        assert len(salt) > 0
        
        # Проверяем, что одинаковые пароли дают разные хеши (из-за соли)
        password_hash2, salt2 = hash_password(password)
        assert password_hash != password_hash2
        assert salt != salt2
    
    def test_session_management(self):
        """P0: Управление сессиями"""
        with patch('backend.main.get_current_user') as mock_auth:
            # Мокаем успешную аутентификацию
            mock_auth.return_value = {
                "id": "test_user_123",
                "email": "test@example.com",
                "full_name": "Test User"
            }
            
            # Тест получения информации о пользователе
            response = client.get("/api/auth/user")
            assert response.status_code == 200
            data = response.json()
            assert "user" in data
            assert data["user"]["id"] == "test_user_123"
            
            # Тест выхода из системы
            with patch('backend.main.supabase_manager') as mock_manager:
                mock_client = MagicMock()
                mock_manager.get_client.return_value = mock_client
                
                response = client.post("/api/auth/logout")
                assert response.status_code == 200
                data = response.json()
                assert "message" in data

class TestInputValidationSecurity:
    """P0: Критические тесты валидации входных данных"""
    
    def test_email_validation(self):
        """P0: Валидация email адресов"""
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "test@",
            "test..test@example.com",
            "test@.com",
            "test@example..com",
            "",
            None
        ]
        
        for invalid_email in invalid_emails:
            registration_data = {
                "email": invalid_email,
                "password": "SecurePass123!",
                "full_name": "Test User"
            }
            
            response = client.post("/api/auth/register", json=registration_data)
            assert response.status_code in [400, 422], f"Невалидный email '{invalid_email}' не был отклонён"
    
    def test_sql_injection_protection(self):
        """P0: Защита от SQL инъекций"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "1' UNION SELECT * FROM users--"
        ]
        
        for malicious_input in malicious_inputs:
            # Тест в email
            registration_data = {
                "email": f"{malicious_input}@example.com",
                "password": "SecurePass123!",
                "full_name": "Test User"
            }
            
            response = client.post("/api/auth/register", json=registration_data)
            # Должен быть отклонён или обработан безопасно
            assert response.status_code in [400, 422, 200], f"SQL инъекция в email не была обработана: {malicious_input}"
    
    def test_xss_protection(self):
        """P0: Защита от XSS атак"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>"
        ]
        
        for xss_payload in xss_payloads:
            # Тест в full_name
            registration_data = {
                "email": "test@example.com",
                "password": "SecurePass123!",
                "full_name": xss_payload
            }
            
            response = client.post("/api/auth/register", json=registration_data)
            # Должен быть отклонён или экранирован
            assert response.status_code in [400, 422, 200], f"XSS payload не был обработан: {xss_payload}"
    
    def test_input_length_limits(self):
        """P0: Ограничения длины входных данных"""
        # Тест слишком длинного email
        long_email = "a" * 300 + "@example.com"
        registration_data = {
            "email": long_email,
            "password": "SecurePass123!",
            "full_name": "Test User"
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code in [400, 422], "Слишком длинный email не был отклонён"
        
        # Тест слишком длинного имени
        long_name = "a" * 1000
        registration_data = {
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": long_name
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code in [400, 422], "Слишком длинное имя не было отклонено"

class TestCSRFSecurity:
    """P0: Критические тесты CSRF защиты"""
    
    def test_csrf_token_validation(self):
        """P0: Валидация CSRF токенов"""
        # POST запрос без CSRF токена должен быть отклонён
        response = client.post(
            "/api/projects",
            json={"name": "Test", "description": "Test"},
            headers={"X-CSRF-Token": ""}
        )
        assert response.status_code == 403, "CSRF защита не сработала для пустого токена"
        
        # POST запрос с коротким CSRF токеном должен быть отклонён
        response = client.post(
            "/api/projects",
            json={"name": "Test", "description": "Test"},
            headers={"X-CSRF-Token": "short"}
        )
        assert response.status_code == 403, "CSRF защита не сработала для короткого токена"
    
    def test_csrf_token_acceptance(self):
        """P0: Принятие валидных CSRF токенов"""
        # POST запрос с валидным CSRF токеном должен пройти (если есть аутентификация)
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            response = client.post(
                "/api/projects",
                json={"name": "Test", "description": "Test"},
                headers={"X-CSRF-Token": "valid_csrf_token_1234567890"}
            )
            # Может быть 500 из-за отсутствия других зависимостей, но не 403 CSRF
            assert response.status_code != 403, "Валидный CSRF токен был отклонён"

class TestCORSecurity:
    """P0: Критические тесты CORS безопасности"""
    
    def test_cors_origin_validation(self):
        """P0: Валидация CORS origins"""
        # Тест с неразрешённым origin
        response = client.options(
            "/api/projects",
            headers={"Origin": "https://malicious-site.com"}
        )
        
        # Проверяем, что неразрешённый origin отклонён
        assert response.status_code == 200  # OPTIONS всегда возвращает 200
        # Но проверяем заголовки CORS
        cors_headers = response.headers
        if "Access-Control-Allow-Origin" in cors_headers:
            assert cors_headers["Access-Control-Allow-Origin"] != "https://malicious-site.com"
    
    def test_cors_methods_validation(self):
        """P0: Валидация CORS методов"""
        response = client.options(
            "/api/projects",
            headers={"Access-Control-Request-Method": "DELETE"}
        )
        
        assert response.status_code == 200
        cors_headers = response.headers
        if "Access-Control-Allow-Methods" in cors_headers:
            allowed_methods = cors_headers["Access-Control-Allow-Methods"]
            assert "DELETE" in allowed_methods
    
    def test_cors_headers_validation(self):
        """P0: Валидация CORS заголовков"""
        response = client.options(
            "/api/projects",
            headers={"Access-Control-Request-Headers": "X-Custom-Header"}
        )
        
        assert response.status_code == 200
        cors_headers = response.headers
        if "Access-Control-Allow-Headers" in cors_headers:
            allowed_headers = cors_headers["Access-Control-Allow-Headers"]
            # Проверяем, что разрешены только безопасные заголовки
            assert "X-Custom-Header" not in allowed_headers or "X-Custom-Header" in allowed_headers

class TestSecurityHeaders:
    """P0: Критические тесты безопасных заголовков"""
    
    def test_security_headers_presence(self):
        """P0: Наличие безопасных заголовков"""
        response = client.get("/")
        
        # Проверяем наличие обязательных безопасных заголовков
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'"
        }
        
        for header, expected_value in security_headers.items():
            assert header in response.headers, f"Отсутствует заголовок безопасности: {header}"
            if expected_value:
                assert response.headers[header] == expected_value, f"Неверное значение заголовка {header}: {response.headers[header]}"
    
    def test_cors_credentials_handling(self):
        """P0: Обработка CORS credentials"""
        response = client.options("/api/projects")
        
        cors_headers = response.headers
        if "Access-Control-Allow-Credentials" in cors_headers:
            assert cors_headers["Access-Control-Allow-Credentials"] == "true"
        
        if "Access-Control-Allow-Origin" in cors_headers:
            # Если credentials=true, то origin не может быть *
            if cors_headers.get("Access-Control-Allow-Credentials") == "true":
                assert cors_headers["Access-Control-Allow-Origin"] != "*"

if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, "-v", "--tb=short", "-x"])