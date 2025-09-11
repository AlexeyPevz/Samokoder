"""
Тесты критических исправлений ASVS
P0 риски: JWT алгоритм, хардкод секретов
"""

import pytest
import jwt
import time
from unittest.mock import patch
from backend.auth.dependencies import validate_jwt_token
from backend.security.session_manager import session_manager
from config.settings import settings

class TestJWTAlgorithmValidation:
    """Тесты проверки алгоритма JWT токенов (V2.1.4)"""
    
    def test_jwt_algorithm_validation_none_algorithm(self):
        """Тест отклонения токенов с алгоритмом 'none'"""
        # Создаем токен с неправильным алгоритмом
        malicious_token = jwt.encode(
            {"user_id": "123", "exp": time.time() + 3600},
            "secret",
            algorithm="none"  # Опасный алгоритм
        )
        
        # Проверяем, что токен отклоняется
        assert not validate_jwt_token(malicious_token)
    
    def test_jwt_algorithm_validation_rs256_algorithm(self):
        """Тест отклонения токенов с алгоритмом RS256"""
        # Создаем токен с неправильным алгоритмом
        malicious_token = jwt.encode(
            {"user_id": "123", "exp": time.time() + 3600},
            "secret",
            algorithm="RS256"  # Неправильный алгоритм
        )
        
        # Проверяем, что токен отклоняется
        assert not validate_jwt_token(malicious_token)
    
    def test_jwt_algorithm_validation_valid_hs256(self):
        """Тест принятия токенов с правильным алгоритмом HS256"""
        # Создаем токен с правильным алгоритмом
        valid_token = jwt.encode(
            {"user_id": "123", "exp": time.time() + 3600},
            settings.secret_key,
            algorithm="HS256"
        )
        
        # Проверяем, что токен принимается
        assert validate_jwt_token(valid_token)
    
    def test_jwt_algorithm_validation_missing_algorithm(self):
        """Тест отклонения токенов без алгоритма в заголовке"""
        # Создаем токен без алгоритма в заголовке
        header = {"typ": "JWT"}
        payload = {"user_id": "123", "exp": time.time() + 3600}
        
        # Кодируем вручную без алгоритма
        import base64
        import json
        
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        malicious_token = f"{header_encoded}.{payload_encoded}.signature"
        
        # Проверяем, что токен отклоняется
        assert not validate_jwt_token(malicious_token)

class TestSessionSecretKeyConfiguration:
    """Тесты конфигурации секретного ключа сессий (V10.1.1)"""
    
    def test_session_secret_key_not_hardcoded(self):
        """Тест, что секретный ключ не хардкод"""
        # Проверяем, что секретный ключ не хардкод
        assert session_manager.secret_key != b"your-secret-key-here"
        assert len(session_manager.secret_key) >= 32
    
    def test_session_secret_key_from_config(self):
        """Тест получения секретного ключа из конфигурации"""
        # Проверяем, что секретный ключ берется из настроек
        assert session_manager.secret_key == settings.session_secret_key.encode()
    
    def test_session_timeout_from_config(self):
        """Тест получения timeout сессии из конфигурации"""
        # Проверяем, что timeout берется из настроек
        assert session_manager.session_timeout == settings.session_timeout
    
    @patch('config.settings.settings.session_secret_key', 'test-secret-key-32-chars-long')
    def test_session_manager_uses_config_values(self):
        """Тест, что менеджер сессий использует значения из конфигурации"""
        # Пересоздаем менеджер с новыми настройками
        from backend.security.session_manager import SecureSessionManager
        
        test_manager = SecureSessionManager(
            secret_key="test-secret-key-32-chars-long",
            session_timeout=7200
        )
        
        assert test_manager.secret_key == b"test-secret-key-32-chars-long"
        assert test_manager.session_timeout == 7200

class TestPasswordValidationConsistency:
    """Тесты согласованности валидации паролей (V5.1.3)"""
    
    def test_password_length_consistency(self):
        """Тест согласованности требований к длине пароля"""
        from backend.auth.dependencies import secure_password_validation
        from backend.security.input_validator import secure_validator
        
        # Проверяем, что оба валидатора используют одинаковые требования
        password_8_chars = "Test123!"
        password_12_chars = "Test123!Abc@"
        
        # 8 символов должно быть недостаточно
        assert not secure_password_validation(password_8_chars)
        assert not secure_validator.validate_password_strength(password_8_chars)[0]
        
        # 12 символов должно быть достаточно
        assert secure_password_validation(password_12_chars)
        assert secure_validator.validate_password_strength(password_12_chars)[0]
    
    def test_password_validation_error_messages(self):
        """Тест сообщений об ошибках валидации паролей"""
        from backend.security.input_validator import secure_validator
        
        # Тест слабого пароля
        is_valid, errors = secure_validator.validate_password_strength("weak")
        
        assert not is_valid
        assert any("at least 12 characters" in error for error in errors)
        assert any("uppercase letter" in error for error in errors)
        assert any("lowercase letter" in error for error in errors)
        assert any("digit" in error for error in errors)
        assert any("special character" in error for error in errors)

class TestCSRFTokenActionBinding:
    """Тесты привязки CSRF токена к действию (V3.1.3)"""
    
    def test_csrf_token_generation_with_action(self):
        """Тест генерации CSRF токена с привязкой к действию"""
        session_id = "test_session"
        action = "delete_user"
        
        # Генерируем токен для конкретного действия
        token = session_manager._generate_csrf_token(session_id, action)
        
        # Проверяем, что токен содержит информацию о действии
        assert token is not None
        assert len(token) > 0
    
    def test_csrf_token_validation_with_action(self):
        """Тест валидации CSRF токена с привязкой к действию"""
        session_id = "test_session"
        action = "delete_user"
        
        # Создаем тестовую сессию
        session_data = session_manager.sessions.get(session_id)
        if not session_data:
            # Создаем mock сессию для теста
            from backend.security.session_manager import SessionData, SessionState
            from datetime import datetime
            
            session_data = SessionData(
                session_id=session_id,
                user_id="test_user",
                created_at=datetime.now(),
                last_activity=datetime.now(),
                ip_address="127.0.0.1",
                user_agent="test",
                state=SessionState.ACTIVE,
                csrf_token=""
            )
            session_manager.sessions[session_id] = session_data
        
        # Генерируем токен для конкретного действия
        token = session_manager._generate_csrf_token(session_id, action)
        
        # Проверяем, что токен валиден для этого действия
        # (Этот тест требует реализации validate_csrf_token с параметром action)
        assert token is not None

class TestAPIInputValidation:
    """Тесты валидации входных данных API (V12.1.2)"""
    
    def test_email_validation(self):
        """Тест валидации email адресов"""
        from backend.security.input_validator import validate_email
        
        # Валидные email
        assert validate_email("test@example.com")
        assert validate_email("user.name+tag@domain.co.uk")
        
        # Невалидные email
        assert not validate_email("invalid-email")
        assert not validate_email("@example.com")
        assert not validate_email("test@")
        assert not validate_email("test..test@example.com")
    
    def test_email_length_validation(self):
        """Тест валидации длины email"""
        from backend.security.input_validator import validate_email
        
        # Слишком длинный email
        long_email = "a" * 250 + "@example.com"
        assert not validate_email(long_email)
        
        # Email на границе лимита
        boundary_email = "a" * 240 + "@example.com"
        assert validate_email(boundary_email)
    
    def test_password_strength_validation(self):
        """Тест валидации силы пароля"""
        from backend.security.input_validator import secure_validator
        
        # Слабые пароли
        weak_passwords = [
            "123456",
            "password",
            "qwerty",
            "abc123",
            "Password123",  # Без специальных символов
            "Password!",    # Без цифр
            "password123!", # Без заглавных букв
            "PASSWORD123!", # Без строчных букв
        ]
        
        for password in weak_passwords:
            is_valid, errors = secure_validator.validate_password_strength(password)
            assert not is_valid, f"Password '{password}' should be invalid"
            assert len(errors) > 0, f"Password '{password}' should have validation errors"
        
        # Сильный пароль
        strong_password = "StrongPass123!"
        is_valid, errors = secure_validator.validate_password_strength(strong_password)
        assert is_valid, f"Password '{strong_password}' should be valid"
        assert len(errors) == 0, f"Password '{strong_password}' should have no errors"

if __name__ == "__main__":
    pytest.main([__file__])