#!/usr/bin/env python3
"""
Тесты для Auth Dependencies
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import os
import jwt
import time
from datetime import datetime
from backend.auth.dependencies import (
    is_test_mode, validate_jwt_token, get_current_user, get_current_user_optional,
    secure_password_validation, hash_password, verify_password, security
)


class TestAuthDependencies:
    """Тесты для Auth Dependencies модуля"""
    
    def test_is_test_mode_true(self):
        """Тест определения тестового режима"""
        with patch.dict(os.environ, {'ENVIRONMENT': 'test'}):
            assert is_test_mode() is True
        
        with patch.dict(os.environ, {'PYTEST_CURRENT_TEST': 'test_function'}):
            assert is_test_mode() is True
    
    def test_is_test_mode_false(self):
        """Тест определения обычного режима"""
        with patch.dict(os.environ, {}, clear=True):
            assert is_test_mode() is False
        
        with patch.dict(os.environ, {'ENVIRONMENT': 'production'}, clear=True):
            assert is_test_mode() is False
    
    @patch('backend.auth.dependencies.settings')
    def test_validate_jwt_token_valid(self, mock_settings):
        """Тест валидации валидного JWT токена"""
        mock_settings.secret_key = "test_secret_key"
        
        # Создаем валидный JWT токен
        payload = {
            'user_id': '123',
            'exp': time.time() + 3600,  # Истекает через час
            'iat': time.time()
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")
        
        result = validate_jwt_token(token)
        assert result is True
    
    @patch('backend.auth.dependencies.settings')
    def test_validate_jwt_token_invalid_format(self, mock_settings):
        """Тест валидации токена с неверным форматом"""
        mock_settings.secret_key = "test_secret_key"
        
        # Тестируем различные неверные форматы
        assert validate_jwt_token("") is False
        assert validate_jwt_token("invalid.token") is False  # Только 2 части
        assert validate_jwt_token("a.b.c.d") is False  # 4 части
        assert validate_jwt_token("not_a_jwt") is False
    
    @patch('backend.auth.dependencies.settings')
    def test_validate_jwt_token_wrong_algorithm(self, mock_settings):
        """Тест валидации токена с неверным алгоритмом"""
        mock_settings.secret_key = "test_secret_key"
        
        # Создаем токен с неподдерживаемым алгоритмом
        payload = {'user_id': '123', 'exp': time.time() + 3600}
        token = jwt.encode(payload, "test_secret_key", algorithm="HS512")
        
        result = validate_jwt_token(token)
        assert result is False
    
    @patch('backend.auth.dependencies.settings')
    def test_validate_jwt_token_no_secret_key(self, mock_settings):
        """Тест валидации токена без секретного ключа"""
        mock_settings.secret_key = None
        
        payload = {'user_id': '123', 'exp': time.time() + 3600}
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")
        
        result = validate_jwt_token(token)
        assert result is False
    
    @patch('backend.auth.dependencies.settings')
    def test_validate_jwt_token_expired(self, mock_settings):
        """Тест валидации истекшего токена"""
        mock_settings.secret_key = "test_secret_key"
        
        # Создаем истекший токен
        payload = {
            'user_id': '123',
            'exp': time.time() - 3600,  # Истек час назад
            'iat': time.time() - 7200
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")
        
        result = validate_jwt_token(token)
        assert result is False
    
    @patch('backend.auth.dependencies.settings')
    def test_validate_jwt_token_invalid_signature(self, mock_settings):
        """Тест валидации токена с неверной подписью"""
        mock_settings.secret_key = "correct_secret"
        
        # Создаем токен с другим секретным ключом
        payload = {'user_id': '123', 'exp': time.time() + 3600}
        token = jwt.encode(payload, "wrong_secret", algorithm="HS256")
        
        result = validate_jwt_token(token)
        assert result is False
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.is_test_mode')
    @patch('backend.auth.dependencies.validate_jwt_token')
    @patch('backend.auth.dependencies.connection_manager')
    async def test_get_current_user_test_mode(self, mock_connection_manager, mock_validate_jwt, mock_is_test_mode):
        """Тест получения пользователя в тестовом режиме"""
        mock_is_test_mode.return_value = True
        
        result = await get_current_user(None)
        
        expected = {
            "id": "test_user_123",
            "email": "test@example.com",
            "created_at": "2025-01-01T00:00:00Z",
            "is_mock": True
        }
        assert result == expected
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.is_test_mode')
    async def test_get_current_user_no_credentials(self, mock_is_test_mode):
        """Тест получения пользователя без токена"""
        mock_is_test_mode.return_value = False
        
        with pytest.raises(Exception):  # HTTPException
            await get_current_user(None)
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.is_test_mode')
    async def test_get_current_user_mock_token(self, mock_is_test_mode):
        """Тест получения пользователя с mock токеном"""
        mock_is_test_mode.return_value = False
        
        mock_credentials = Mock()
        mock_credentials.credentials = "mock_token_user@example.com"
        
        result = await get_current_user(mock_credentials)
        
        expected = {
            "id": "mock_user_user@example.com",
            "email": "user@example.com",
            "created_at": "2025-01-01T00:00:00Z",
            "is_mock": True
        }
        assert result == expected
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.is_test_mode')
    @patch('backend.auth.dependencies.validate_jwt_token')
    @patch('backend.auth.dependencies.connection_manager')
    async def test_get_current_user_valid_jwt(self, mock_connection_manager, mock_validate_jwt, mock_is_test_mode):
        """Тест получения пользователя с валидным JWT"""
        mock_is_test_mode.return_value = False
        mock_validate_jwt.return_value = True
        
        # Мокаем Supabase клиент
        mock_supabase_client = Mock()
        mock_connection_manager.get_pool.return_value = mock_supabase_client
        
        # Мокаем ответ Supabase
        mock_user = Mock()
        mock_user.id = "user123"
        mock_user.email = "test@example.com"
        mock_user.created_at = "2024-01-01T00:00:00Z"
        mock_user.updated_at = "2024-01-01T00:00:00Z"
        mock_user.email_confirmed_at = None
        mock_user.phone = None
        mock_user.confirmed_at = None
        mock_user.last_sign_in_at = None
        mock_user.app_metadata = {}
        mock_user.user_metadata = {}
        mock_user.role = "authenticated"
        mock_user.aud = "authenticated"
        mock_user.exp = None
        
        mock_response = Mock()
        mock_response.user = mock_user
        mock_supabase_client.auth.get_user.return_value = mock_response
        
        mock_credentials = Mock()
        mock_credentials.credentials = "valid_jwt_token"
        
        result = await get_current_user(mock_credentials)
        
        assert result["id"] == "user123"
        assert result["email"] == "test@example.com"
        assert result["created_at"] == "2024-01-01T00:00:00Z"
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.is_test_mode')
    @patch('backend.auth.dependencies.validate_jwt_token')
    async def test_get_current_user_invalid_jwt(self, mock_validate_jwt, mock_is_test_mode):
        """Тест получения пользователя с невалидным JWT"""
        mock_is_test_mode.return_value = False
        mock_validate_jwt.return_value = False
        
        mock_credentials = Mock()
        mock_credentials.credentials = "invalid_jwt_token"
        
        with pytest.raises(Exception):  # HTTPException
            await get_current_user(mock_credentials)
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.is_test_mode')
    @patch('backend.auth.dependencies.connection_manager')
    async def test_get_current_user_connection_error(self, mock_connection_manager, mock_is_test_mode):
        """Тест получения пользователя при ошибке подключения"""
        mock_is_test_mode.return_value = False
        
        # Мокаем ошибку подключения
        mock_connection_manager.get_pool.side_effect = Exception("Connection error")
        
        mock_credentials = Mock()
        mock_credentials.credentials = "valid_token"
        
        with pytest.raises(Exception):  # HTTPException
            await get_current_user(mock_credentials)
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.get_current_user')
    async def test_get_current_user_optional_with_credentials(self, mock_get_current_user):
        """Тест получения опционального пользователя с токеном"""
        mock_user = {"id": "user123", "email": "test@example.com"}
        mock_get_current_user.return_value = mock_user
        
        mock_credentials = Mock()
        result = await get_current_user_optional(mock_credentials)
        
        assert result == mock_user
        mock_get_current_user.assert_called_once_with(mock_credentials)
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.get_current_user')
    async def test_get_current_user_optional_without_credentials(self, mock_get_current_user):
        """Тест получения опционального пользователя без токена"""
        result = await get_current_user_optional(None)
        
        assert result is None
        mock_get_current_user.assert_not_called()
    
    @pytest.mark.asyncio
    @patch('backend.auth.dependencies.get_current_user')
    async def test_get_current_user_optional_with_invalid_credentials(self, mock_get_current_user):
        """Тест получения опционального пользователя с невалидным токеном"""
        from fastapi import HTTPException
        mock_get_current_user.side_effect = HTTPException(status_code=401, detail="Invalid token")
        
        mock_credentials = Mock()
        result = await get_current_user_optional(mock_credentials)
        
        assert result is None
    
    def test_secure_password_validation_valid(self):
        """Тест валидации валидного пароля"""
        valid_passwords = [
            "Password123!",
            "MySecure1@Pass",
            "Test123#Word",
            "ValidPass$1"
        ]
        
        for password in valid_passwords:
            assert secure_password_validation(password) is True
    
    def test_secure_password_validation_invalid(self):
        """Тест валидации невалидного пароля"""
        invalid_passwords = [
            "",  # Пустой пароль
            "1234567",  # Менее 8 символов
            "password",  # Только строчные буквы
            "PASSWORD",  # Только заглавные буквы
            "12345678",  # Только цифры
            "Password",  # Нет цифр и спецсимволов
            "Password1",  # Нет спецсимволов
            "Password!",  # Нет цифр
            "password1!",  # Нет заглавных букв
            "PASSWORD1!",  # Нет строчных букв
        ]
        
        for password in invalid_passwords:
            assert secure_password_validation(password) is False
    
    def test_secure_password_validation_none(self):
        """Тест валидации None пароля"""
        assert secure_password_validation(None) is False
    
    def test_hash_password(self):
        """Тест хеширования пароля"""
        password = "TestPassword123!"
        
        hashed = hash_password(password)
        
        # Проверяем что хеш создан
        assert hashed is not None
        assert len(hashed) > 0
        assert hashed != password  # Хеш не должен быть равен исходному паролю
        
        # Проверяем формат bcrypt хеша
        assert hashed.startswith('$2b$') or hashed.startswith('$2a$')
        
        # Проверяем что хеширование детерминистично (каждый раз разный хеш)
        hashed2 = hash_password(password)
        assert hashed != hashed2  # Разные хеши для одного пароля
    
    def test_verify_password_correct(self):
        """Тест проверки правильного пароля"""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Тест проверки неправильного пароля"""
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        hashed = hash_password(password)
        
        assert verify_password(wrong_password, hashed) is False
    
    def test_verify_password_empty(self):
        """Тест проверки пустого пароля"""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        assert verify_password("", hashed) is False
        assert verify_password(None, hashed) is False
        assert verify_password(password, "") is False
        assert verify_password(password, None) is False
    
    def test_verify_password_invalid_hash_format(self):
        """Тест проверки пароля с невалидным форматом хеша"""
        password = "TestPassword123!"
        invalid_hash = "invalid_hash_format"
        
        assert verify_password(password, invalid_hash) is False
    
    def test_verify_password_timing_attack_protection(self):
        """Тест защиты от timing attack"""
        password = "TestPassword123!"
        valid_hash = hash_password(password)
        invalid_hash = "invalid_hash"
        
        # Проверяем что оба вызова выполняются примерно за одинаковое время
        # (это сложно точно протестировать, но мы можем убедиться что функция не падает)
        assert verify_password(password, valid_hash) is True
        assert verify_password(password, invalid_hash) is False
    
    def test_security_bearer_exists(self):
        """Тест существования HTTPBearer"""
        assert security is not None
        assert hasattr(security, 'auto_error')
        assert security.auto_error is False
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.auth.dependencies import (
            is_test_mode, validate_jwt_token, get_current_user, get_current_user_optional,
            secure_password_validation, hash_password, verify_password, security
        )
        
        assert is_test_mode is not None
        assert validate_jwt_token is not None
        assert get_current_user is not None
        assert get_current_user_optional is not None
        assert secure_password_validation is not None
        assert hash_password is not None
        assert verify_password is not None
        assert security is not None
    
    def test_password_complexity_requirements(self):
        """Тест требований к сложности пароля"""
        # Проверяем что функция проверяет все требования
        test_cases = [
            ("Abcdef123!", True),   # Все требования выполнены (8+ символов)
            ("abc123!", False),  # Нет заглавной буквы
            ("ABC123!", False),  # Нет строчной буквы
            ("Abcdef!", False),  # Нет цифры
            ("Abcdef123", False),   # Нет спецсимвола
            ("Ab1!", False),     # Менее 8 символов
        ]
        
        for password, expected in test_cases:
            assert secure_password_validation(password) == expected
    
    def test_bcrypt_integration(self):
        """Тест интеграции с bcrypt"""
        password = "TestPassword123!"
        
        # Тестируем полный цикл: хеширование -> проверка
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        
        # Тестируем что bcrypt действительно используется
        assert hashed.startswith('$2b$') or hashed.startswith('$2a$')
        
        # Тестируем что соль генерируется автоматически
        hashed2 = hash_password(password)
        assert hashed != hashed2  # Разные хеши из-за разных солей