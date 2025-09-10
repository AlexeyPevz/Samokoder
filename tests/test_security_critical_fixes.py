"""
Тесты критических исправлений безопасности (P0)
Инженер по безопасности с 20-летним опытом
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request, HTTPException

from security_patches.minimal_critical_fixes import (
    MinimalSecurityFixes, SecurityMiddleware, 
    apply_all_fixes, security_fixes
)

class TestAuthenticationSecurity:
    """Тесты безопасности аутентификации (V2)"""
    
    def test_mfa_secret_generation(self):
        """V2.1.1 - Тест генерации MFA секрета"""
        secret = security_fixes.generate_mfa_secret()
        
        assert secret is not None
        assert len(secret) >= 32
        assert isinstance(secret, str)
    
    def test_mfa_code_verification(self):
        """V2.1.1 - Тест проверки MFA кода"""
        secret = security_fixes.generate_mfa_secret()
        
        # Тест с валидным кодом (mock)
        with patch('security_patches.minimal_critical_fixes.pyotp') as mock_pyotp:
            mock_totp = MagicMock()
            mock_totp.verify.return_value = True
            mock_pyotp.TOTP.return_value = mock_totp
            
            result = security_fixes.verify_mfa_code(secret, "123456")
            assert result is True
    
    def test_password_hashing(self):
        """V2.1.2 - Тест хеширования пароля"""
        password = "TestPassword123!"
        hash_result, salt = security_fixes.hash_password(password)
        
        assert hash_result is not None
        assert salt is not None
        assert len(hash_result) == 64  # SHA-256 hex length
        assert len(salt) == 32  # 16 bytes hex encoded
    
    def test_password_verification(self):
        """V2.1.2 - Тест проверки пароля"""
        password = "TestPassword123!"
        hash_result, salt = security_fixes.hash_password(password)
        
        # Правильный пароль
        assert security_fixes.verify_password(password, hash_result, salt) is True
        
        # Неправильный пароль
        assert security_fixes.verify_password("WrongPassword", hash_result, salt) is False
    
    def test_brute_force_protection(self):
        """V2.1.3 - Тест защиты от brute force"""
        email = "test@example.com"
        
        # Первые попытки должны проходить
        for i in range(5):
            assert security_fixes.check_brute_force(email) is True
            security_fixes.record_failed_attempt(email)
        
        # После 5 попыток должна быть блокировка
        assert security_fixes.check_brute_force(email) is False
        
        # Сброс попыток
        security_fixes.reset_failed_attempts(email)
        assert security_fixes.check_brute_force(email) is True

class TestSessionSecurity:
    """Тесты безопасности сессий (V3)"""
    
    def test_secure_session_creation(self):
        """V3.1.1 - Тест создания безопасной сессии"""
        user_id = "test_user_123"
        session_id = security_fixes.create_secure_session(user_id)
        
        assert session_id is not None
        assert len(session_id) >= 32
        assert isinstance(session_id, str)
    
    def test_session_validation(self):
        """V3.1.1 - Тест валидации сессии"""
        # Валидная сессия
        valid_session = security_fixes.create_secure_session("test_user")
        assert security_fixes.validate_session(valid_session) is True
        
        # Невалидная сессия
        assert security_fixes.validate_session("") is False
        assert security_fixes.validate_session("short") is False
        assert security_fixes.validate_session(None) is False

class TestAccessControl:
    """Тесты контроля доступа (V4)"""
    
    def test_permission_checking(self):
        """V4.1.1 - Тест проверки прав доступа"""
        # Админ может все
        assert security_fixes.check_permissions("admin", "user") is True
        assert security_fixes.check_permissions("admin", "admin") is True
        
        # Пользователь может только пользовательские права
        assert security_fixes.check_permissions("user", "user") is True
        assert security_fixes.check_permissions("user", "admin") is False
        
        # Гость не может ничего
        assert security_fixes.check_permissions("guest", "user") is False
        assert security_fixes.check_permissions("guest", "admin") is False

class TestInputValidation:
    """Тесты валидации входных данных (V5)"""
    
    def test_input_validation(self):
        """V5.1.1 - Тест валидации ввода"""
        # Нормальный ввод
        normal_input = "Hello World"
        validated = security_fixes.validate_input(normal_input)
        assert validated == "Hello World"
        
        # Ввод с опасными символами
        dangerous_input = "Hello <script>alert('xss')</script> World"
        validated = security_fixes.validate_input(dangerous_input)
        assert "<script>" not in validated
        assert "alert" not in validated
        
        # Пустой ввод
        assert security_fixes.validate_input("") == ""
        assert security_fixes.validate_input(None) == ""
    
    def test_sql_injection_detection(self):
        """V5.1.1 - Тест обнаружения SQL injection"""
        # SQL injection попытки
        sql_attacks = [
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users --",
            "admin' OR '1'='1",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --"
        ]
        
        for attack in sql_attacks:
            assert security_fixes.detect_sql_injection(attack) is True
        
        # Нормальный ввод
        normal_inputs = [
            "Hello World",
            "user@example.com",
            "normal search query"
        ]
        
        for normal_input in normal_inputs:
            assert security_fixes.detect_sql_injection(normal_input) is False
    
    def test_xss_detection(self):
        """V5.1.1 - Тест обнаружения XSS"""
        # XSS попытки
        xss_attacks = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<iframe src='javascript:alert(\"xss\")'></iframe>"
        ]
        
        for attack in xss_attacks:
            assert security_fixes.detect_xss(attack) is True
        
        # Нормальный ввод
        normal_inputs = [
            "Hello World",
            "This is a normal text",
            "User comment without HTML"
        ]
        
        for normal_input in normal_inputs:
            assert security_fixes.detect_xss(normal_input) is False

class TestErrorHandling:
    """Тесты обработки ошибок (V7)"""
    
    def test_safe_error_response(self):
        """V7.1.1 - Тест безопасного ответа об ошибке"""
        error = Exception("Test error with sensitive data")
        response = security_fixes.safe_error_response(error)
        
        assert "error" in response
        assert "message" in response
        assert "Test error" not in response["error"]  # Не должно содержать детали
        assert "sensitive data" not in response["error"]

class TestSecretsManagement:
    """Тесты управления секретами (V10)"""
    
    def test_secret_retrieval(self):
        """V10.1.1 - Тест получения секретов"""
        with patch.dict('os.environ', {'TEST_SECRET': 'test_value'}):
            secret = security_fixes.get_secret('TEST_SECRET')
            assert secret == 'test_value'
    
    def test_secrets_validation(self):
        """V10.1.1 - Тест проверки секретов"""
        with patch.dict('os.environ', {
            'SECRET_KEY': 'test_secret',
            'API_ENCRYPTION_KEY': 'test_encryption_key',
            'SUPABASE_URL': 'https://test.supabase.co',
            'SUPABASE_ANON_KEY': 'test_anon_key'
        }):
            missing = security_fixes.validate_secrets()
            assert len(missing) == 0
        
        # Тест с отсутствующими секретами
        with patch.dict('os.environ', {}, clear=True):
            missing = security_fixes.validate_secrets()
            assert len(missing) == 4
            assert 'SECRET_KEY' in missing

class TestAPISecurity:
    """Тесты безопасности API (V12)"""
    
    def test_rate_limiting(self):
        """V12.1.1 - Тест rate limiting"""
        client_ip = "192.168.1.1"
        endpoint = "/api/test"
        
        # Первые запросы должны проходить
        for i in range(50):
            assert security_fixes.check_rate_limit(client_ip, endpoint) is True
        
        # После лимита должны блокироваться
        for i in range(60):
            result = security_fixes.check_rate_limit(client_ip, endpoint)
            if i < 50:
                assert result is True
            else:
                assert result is False
    
    def test_ip_blocking(self):
        """V12.1.1 - Тест блокировки IP"""
        ip = "192.168.1.100"
        
        # IP не заблокирован
        assert security_fixes.is_ip_blocked(ip) is False
        
        # Блокируем IP
        security_fixes.block_ip(ip, "Test blocking")
        assert security_fixes.is_ip_blocked(ip) is True

class TestSecurityMiddleware:
    """Тесты middleware безопасности"""
    
    def test_middleware_creation(self):
        """Тест создания middleware"""
        app = FastAPI()
        middleware = SecurityMiddleware(app)
        assert middleware is not None
    
    def test_middleware_with_test_client(self):
        """Тест middleware с тестовым клиентом"""
        app = FastAPI()
        app.add_middleware(SecurityMiddleware)
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # Нормальный запрос
        response = client.get("/test")
        assert response.status_code == 200
        
        # Тест с заблокированным IP
        security_fixes.block_ip("127.0.0.1", "Test")
        response = client.get("/test")
        assert response.status_code == 403

class TestIntegrationFixes:
    """Интеграционные тесты исправлений"""
    
    def test_apply_auth_fixes(self):
        """Тест применения исправлений аутентификации"""
        with patch.dict('os.environ', {
            'SECRET_KEY': 'test_secret',
            'API_ENCRYPTION_KEY': 'test_encryption_key',
            'SUPABASE_URL': 'https://test.supabase.co',
            'SUPABASE_ANON_KEY': 'test_anon_key'
        }):
            from security_patches.minimal_critical_fixes import apply_auth_fixes
            result = apply_auth_fixes()
            assert result is True
    
    def test_apply_all_fixes(self):
        """Тест применения всех исправлений"""
        with patch.dict('os.environ', {
            'SECRET_KEY': 'test_secret',
            'API_ENCRYPTION_KEY': 'test_encryption_key',
            'SUPABASE_URL': 'https://test.supabase.co',
            'SUPABASE_ANON_KEY': 'test_anon_key'
        }):
            result = apply_all_fixes()
            assert result is True

class TestPerformanceSecurity:
    """Тесты производительности безопасности"""
    
    def test_password_hashing_performance(self):
        """Тест производительности хеширования паролей"""
        password = "TestPassword123!"
        
        start_time = time.time()
        for _ in range(100):
            security_fixes.hash_password(password)
        end_time = time.time()
        
        # Хеширование 100 паролей не должно занимать больше 5 секунд
        assert (end_time - start_time) < 5.0
    
    def test_rate_limiting_performance(self):
        """Тест производительности rate limiting"""
        client_ip = "192.168.1.1"
        endpoint = "/api/test"
        
        start_time = time.time()
        for _ in range(1000):
            security_fixes.check_rate_limit(client_ip, endpoint)
        end_time = time.time()
        
        # 1000 проверок rate limiting не должны занимать больше 1 секунды
        assert (end_time - start_time) < 1.0

# Запуск тестов
if __name__ == "__main__":
    pytest.main([__file__, "-v"])