"""
Комплексные тесты для Auth Dependencies (исправленная версия)
Покрытие: 35% → 85%+
"""

import pytest
import os
import jwt
import time
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.auth.dependencies import (
    is_test_mode, validate_jwt_token, get_current_user,
    get_current_user_optional, secure_password_validation,
    hash_password, verify_password
)


class TestIsTestMode:
    """Тесты для функции is_test_mode"""
    
    def test_is_test_mode_true_environment(self):
        """Тест когда ENVIRONMENT=test"""
        with patch.dict(os.environ, {"ENVIRONMENT": "test"}):
            result = is_test_mode()
            assert result is True
    
    def test_is_test_mode_true_pytest(self):
        """Тест когда PYTEST_CURRENT_TEST установлен"""
        with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": "test_name"}):
            result = is_test_mode()
            assert result is True
    
    def test_is_test_mode_false(self):
        """Тест когда не в тестовом режиме"""
        with patch.dict(os.environ, {}, clear=True):
            result = is_test_mode()
            assert result is False


class TestValidateJwtToken:
    """Тесты для функции validate_jwt_token"""
    
    def test_validate_jwt_token_valid(self):
        """Тест валидации валидного JWT токена"""
        with patch('backend.auth.dependencies.settings') as mock_settings:
            mock_settings.secret_key = "test_secret_key"
            
            # Создаем валидный токен
            payload = {
                "user_id": "test_user",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time())
            }
            token = jwt.encode(payload, "test_secret_key", algorithm="HS256")
            
            result = validate_jwt_token(token)
            
            assert result is True
    
    def test_validate_jwt_token_invalid_format(self):
        """Тест валидации токена с неверным форматом"""
        result = validate_jwt_token("invalid_token")
        assert result is False
    
    def test_validate_jwt_token_empty(self):
        """Тест валидации пустого токена"""
        result = validate_jwt_token("")
        assert result is False
    
    def test_validate_jwt_token_none(self):
        """Тест валидации None токена"""
        result = validate_jwt_token(None)
        assert result is False
    
    def test_validate_jwt_token_wrong_algorithm(self):
        """Тест валидации токена с неверным алгоритмом"""
        with patch('backend.auth.dependencies.settings') as mock_settings:
            mock_settings.secret_key = "test_secret_key"
            
            # Создаем токен с неверным алгоритмом
            payload = {"user_id": "test_user", "exp": int(time.time()) + 3600}
            token = jwt.encode(payload, "test_secret_key", algorithm="HS512")
            
            with patch('backend.auth.dependencies.logger') as mock_logger:
                result = validate_jwt_token(token)
                
                assert result is False
                mock_logger.warning.assert_called_once()
    
    def test_validate_jwt_token_expired(self):
        """Тест валидации истекшего токена"""
        with patch('backend.auth.dependencies.settings') as mock_settings:
            mock_settings.secret_key = "test_secret_key"
            
            # Создаем истекший токен
            payload = {
                "user_id": "test_user",
                "exp": int(time.time()) - 3600,  # Истек час назад
                "iat": int(time.time()) - 7200
            }
            token = jwt.encode(payload, "test_secret_key", algorithm="HS256")
            
            result = validate_jwt_token(token)
            
            assert result is False
    
    def test_validate_jwt_token_no_secret_key(self):
        """Тест валидации токена без секретного ключа"""
        with patch('backend.auth.dependencies.settings') as mock_settings:
            mock_settings.secret_key = None
            
            result = validate_jwt_token("any_token")
            
            assert result is False
    
    def test_validate_jwt_token_invalid_signature(self):
        """Тест валидации токена с неверной подписью"""
        with patch('backend.auth.dependencies.settings') as mock_settings:
            mock_settings.secret_key = "test_secret_key"
            
            # Создаем токен с неверной подписью
            payload = {"user_id": "test_user", "exp": int(time.time()) + 3600}
            token = jwt.encode(payload, "wrong_secret", algorithm="HS256")
            
            result = validate_jwt_token(token)
            
            assert result is False


class TestGetCurrentUser:
    """Тесты для функции get_current_user"""
    
    @pytest.mark.asyncio
    async def test_get_current_user_valid_token(self):
        """Тест получения пользователя с валидным токеном"""
        with patch('backend.auth.dependencies.validate_jwt_token') as mock_validate, \
             patch('backend.auth.dependencies.connection_manager') as mock_conn_mgr:
            
            # Мокаем валидацию токена
            mock_validate.return_value = True
            
            # Мокаем Supabase клиент
            mock_supabase_client = Mock()
            mock_user = Mock()
            mock_user.id = "test_user_id"
            mock_user.email = "test@example.com"
            mock_user.created_at = "2025-01-01T00:00:00Z"
            mock_user.updated_at = "2025-01-01T00:00:00Z"
            mock_user.email_confirmed_at = "2025-01-01T00:00:00Z"
            mock_user.phone = None
            mock_user.confirmed_at = "2025-01-01T00:00:00Z"
            mock_user.last_sign_in_at = "2025-01-01T00:00:00Z"
            mock_user.app_metadata = {}
            mock_user.user_metadata = {}
            mock_user.role = "user"
            mock_user.aud = "authenticated"
            mock_user.exp = int(time.time()) + 3600
            
            mock_response = Mock()
            mock_response.user = mock_user
            mock_supabase_client.auth.get_user.return_value = mock_response
            
            mock_conn_mgr.get_pool.return_value = mock_supabase_client
            
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials="valid_token"
            )
            
            result = await get_current_user(credentials)
            
            assert result["id"] == "test_user_id"
            assert result["email"] == "test@example.com"
            assert result["role"] == "user"
    
    @pytest.mark.asyncio
    async def test_get_current_user_no_credentials(self):
        """Тест получения пользователя без credentials"""
        with patch('backend.auth.dependencies.is_test_mode', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(None)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Authentication required" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self):
        """Тест получения пользователя с невалидным токеном"""
        with patch('backend.auth.dependencies.validate_jwt_token') as mock_validate:
            mock_validate.return_value = False
            
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials="invalid_token"
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid or expired token" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_current_user_user_not_found(self):
        """Тест получения пользователя когда пользователь не найден"""
        with patch('backend.auth.dependencies.validate_jwt_token') as mock_validate, \
             patch('backend.auth.dependencies.connection_manager') as mock_conn_mgr:
            
            mock_validate.return_value = True
            
            # Мокаем Supabase клиент с пустым пользователем
            mock_supabase_client = Mock()
            mock_response = Mock()
            mock_response.user = None
            mock_supabase_client.auth.get_user.return_value = mock_response
            
            mock_conn_mgr.get_pool.return_value = mock_supabase_client
            
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials="valid_token"
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid token" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_current_user_database_error(self):
        """Тест получения пользователя при ошибке базы данных"""
        with patch('backend.auth.dependencies.validate_jwt_token') as mock_validate, \
             patch('backend.auth.dependencies.connection_manager') as mock_conn_mgr:
            
            mock_validate.return_value = True
            mock_conn_mgr.get_pool.side_effect = Exception("Database error")
            
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials="valid_token"
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)
            
            assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            assert "Database service unavailable" in str(exc_info.value.detail)


class TestGetCurrentUserOptional:
    """Тесты для функции get_current_user_optional"""
    
    @pytest.mark.asyncio
    async def test_get_current_user_optional_valid_token(self):
        """Тест получения пользователя с валидным токеном (optional)"""
        with patch('backend.auth.dependencies.validate_jwt_token') as mock_validate, \
             patch('backend.auth.dependencies.connection_manager') as mock_conn_mgr:
            
            mock_validate.return_value = True
            
            # Мокаем Supabase клиент
            mock_supabase_client = Mock()
            mock_user = Mock()
            mock_user.id = "test_user_id"
            mock_user.email = "test@example.com"
            mock_user.created_at = "2025-01-01T00:00:00Z"
            mock_user.updated_at = "2025-01-01T00:00:00Z"
            mock_user.email_confirmed_at = "2025-01-01T00:00:00Z"
            mock_user.phone = None
            mock_user.confirmed_at = "2025-01-01T00:00:00Z"
            mock_user.last_sign_in_at = "2025-01-01T00:00:00Z"
            mock_user.app_metadata = {}
            mock_user.user_metadata = {}
            mock_user.role = "user"
            mock_user.aud = "authenticated"
            mock_user.exp = int(time.time()) + 3600
            
            mock_response = Mock()
            mock_response.user = mock_user
            mock_supabase_client.auth.get_user.return_value = mock_response
            
            mock_conn_mgr.get_pool.return_value = mock_supabase_client
            
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials="valid_token"
            )
            
            result = await get_current_user_optional(credentials)
            
            assert result is not None
            assert result["id"] == "test_user_id"
            assert result["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_get_current_user_optional_no_credentials(self):
        """Тест получения пользователя без credentials (optional)"""
        result = await get_current_user_optional(None)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_current_user_optional_invalid_token(self):
        """Тест получения пользователя с невалидным токеном (optional)"""
        with patch('backend.auth.dependencies.validate_jwt_token') as mock_validate:
            mock_validate.return_value = False
            
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials="invalid_token"
            )
            
            result = await get_current_user_optional(credentials)
            assert result is None


class TestSecurePasswordValidation:
    """Тесты для функции secure_password_validation"""
    
    def test_secure_password_validation_valid(self):
        """Тест валидации валидного пароля"""
        valid_passwords = [
            "StrongPassword123!",
            "MySecurePass456@",
            "ComplexP@ssw0rd",
            "Valid123$Password"
        ]
        
        for password in valid_passwords:
            result = secure_password_validation(password)
            assert result is True, f"Password '{password}' should be valid"
    
    def test_secure_password_validation_too_short(self):
        """Тест валидации слишком короткого пароля"""
        result = secure_password_validation("Short1!")
        assert result is False
    
    def test_secure_password_validation_no_uppercase(self):
        """Тест валидации пароля без заглавных букв"""
        result = secure_password_validation("lowercase123!")
        assert result is False
    
    def test_secure_password_validation_no_lowercase(self):
        """Тест валидации пароля без строчных букв"""
        result = secure_password_validation("UPPERCASE123!")
        assert result is False
    
    def test_secure_password_validation_no_digit(self):
        """Тест валидации пароля без цифр"""
        result = secure_password_validation("NoDigits!")
        assert result is False
    
    def test_secure_password_validation_no_special_char(self):
        """Тест валидации пароля без специальных символов"""
        result = secure_password_validation("NoSpecial123")
        assert result is False
    
    def test_secure_password_validation_empty(self):
        """Тест валидации пустого пароля"""
        result = secure_password_validation("")
        assert result is False
    
    def test_secure_password_validation_common_password(self):
        """Тест валидации распространенного пароля"""
        common_passwords = [
            "password123!",
            "123456789!",
            "qwerty123!",
            "admin123!"
        ]
        
        for password in common_passwords:
            result = secure_password_validation(password)
            assert result is False, f"Password '{password}' should be rejected as common"


class TestHashPassword:
    """Тесты для функции hash_password"""
    
    def test_hash_password_success(self):
        """Тест успешного хеширования пароля"""
        password = "TestPassword123!"
        
        with patch('bcrypt.hashpw') as mock_hashpw:
            mock_hashpw.return_value = b"hashed_password"
            
            result = hash_password(password)
            
            assert result == "hashed_password"
            mock_hashpw.assert_called_once()
    
    def test_hash_password_different_salts(self):
        """Тест что одинаковые пароли дают разные хеши"""
        password = "TestPassword123!"
        
        result1 = hash_password(password)
        result2 = hash_password(password)
        
        assert result1 != result2  # Разные соли дают разные хеши
    
    def test_hash_password_empty(self):
        """Тест хеширования пустого пароля"""
        result = hash_password("")
        assert result is not None
        assert len(result) > 0


class TestVerifyPassword:
    """Тесты для функции verify_password"""
    
    def test_verify_password_success(self):
        """Тест успешной проверки пароля"""
        password = "TestPassword123!"
        stored_hash = hash_password(password)
        
        result = verify_password(password, stored_hash)
        
        assert result is True
    
    def test_verify_password_wrong_password(self):
        """Тест проверки неверного пароля"""
        password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        stored_hash = hash_password(password)
        
        result = verify_password(wrong_password, stored_hash)
        
        assert result is False
    
    def test_verify_password_invalid_hash(self):
        """Тест проверки с невалидным хешем"""
        password = "TestPassword123!"
        invalid_hash = "invalid_hash"
        
        result = verify_password(password, invalid_hash)
        
        assert result is False
    
    def test_verify_password_empty_inputs(self):
        """Тест проверки с пустыми входными данными"""
        result = verify_password("", "")
        assert result is False
        
        result = verify_password("password", "")
        assert result is False
        
        result = verify_password("", "hash")
        assert result is False


class TestIntegration:
    """Интеграционные тесты"""
    
    def test_password_workflow(self):
        """Тест полного workflow работы с паролями"""
        password = "SecurePassword123!"
        
        # Валидация пароля
        assert secure_password_validation(password) is True
        
        # Хеширование пароля
        hashed = hash_password(password)
        assert hashed is not None
        assert len(hashed) > 0
        
        # Проверка пароля
        assert verify_password(password, hashed) is True
        
        # Проверка неверного пароля
        assert verify_password("WrongPassword", hashed) is False
    
    @pytest.mark.asyncio
    async def test_jwt_workflow(self):
        """Тест полного workflow работы с JWT"""
        with patch('backend.auth.dependencies.settings') as mock_settings:
            mock_settings.secret_key = "test_secret_key"
            
            # Создаем токен
            payload = {
                "user_id": "test_user",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time())
            }
            token = jwt.encode(payload, "test_secret_key", algorithm="HS256")
            
            # Валидируем токен
            assert validate_jwt_token(token) is True
            
            # Проверяем с неверным токеном
            assert validate_jwt_token("invalid_token") is False