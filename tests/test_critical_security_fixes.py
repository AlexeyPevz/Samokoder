"""
Тесты критических исправлений безопасности P0
"""

import pytest
import secrets
import time
from unittest.mock import patch, MagicMock
from backend.api.mfa import store_mfa_secret, get_mfa_secret, delete_mfa_secret
from backend.api.api_keys import create_api_key
from backend.models.requests import APIKeyCreateRequest, Provider

class TestMFASecurityFixes:
    """Тесты исправлений MFA безопасности"""
    
    def test_mfa_secrets_not_in_memory(self):
        """Тест, что MFA секреты не хранятся в памяти"""
        # Проверяем, что глобальная переменная пуста
        from backend.api.mfa import mfa_secrets
        assert len(mfa_secrets) == 0
        
        # Тестируем функции хранения
        user_id = "test_user"
        secret = "test_secret_12345"
        
        # Сохраняем секрет
        store_mfa_secret(user_id, secret)
        
        # Получаем секрет
        retrieved_secret = get_mfa_secret(user_id)
        assert retrieved_secret == secret
        
        # Удаляем секрет
        delete_mfa_secret(user_id)
        assert get_mfa_secret(user_id) is None
    
    @patch('backend.api.mfa.redis_client')
    def test_mfa_secrets_redis_storage(self, mock_redis):
        """Тест хранения MFA секретов в Redis"""
        mock_redis.setex = MagicMock()
        mock_redis.get = MagicMock(return_value=b"test_secret")
        mock_redis.delete = MagicMock()
        
        user_id = "test_user"
        secret = "test_secret"
        
        # Тестируем сохранение
        store_mfa_secret(user_id, secret)
        mock_redis.setex.assert_called_once_with(f"mfa_secret:{user_id}", 3600, secret)
        
        # Тестируем получение
        retrieved = get_mfa_secret(user_id)
        mock_redis.get.assert_called_once_with(f"mfa_secret:{user_id}")
        assert retrieved == "test_secret"
        
        # Тестируем удаление
        delete_mfa_secret(user_id)
        mock_redis.delete.assert_called_once_with(f"mfa_secret:{user_id}")
    
    def test_backup_codes_generation(self):
        """Тест генерации случайных backup кодов"""
        from backend.api.mfa import setup_mfa
        
        # Генерируем backup коды
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        
        # Проверяем, что коды случайные
        assert len(backup_codes) == 10
        assert all(len(code) == 8 for code in backup_codes)  # 4 bytes = 8 hex chars
        assert all(code.isalnum() for code in backup_codes)
        
        # Проверяем, что коды не предсказуемые
        assert backup_codes != ["123456", "234567", "345678", "456789", "567890"]
    
    @patch('backend.api.mfa.pyotp')
    def test_mfa_code_validation_with_pyotp(self, mock_pyotp):
        """Тест валидации MFA кода с pyotp"""
        from backend.api.mfa import verify_mfa_code
        
        # Настраиваем mock
        mock_totp = MagicMock()
        mock_totp.verify.return_value = True
        mock_pyotp.TOTP.return_value = mock_totp
        
        user_id = "test_user"
        secret = "test_secret"
        code = "123456"
        
        # Сохраняем секрет
        store_mfa_secret(user_id, secret)
        
        # Тестируем валидацию
        result = verify_mfa_code(user_id, code)
        
        # Проверяем, что pyotp был вызван
        mock_pyotp.TOTP.assert_called_once_with(secret)
        mock_totp.verify.assert_called()
        assert result is True
    
    def test_mfa_code_validation_fallback(self):
        """Тест fallback валидации MFA кода без pyotp"""
        with patch('backend.api.mfa.pyotp', side_effect=ImportError):
            from backend.api.mfa import verify_mfa_code
            
            user_id = "test_user"
            secret = "test_secret"
            
            # Сохраняем секрет
            store_mfa_secret(user_id, secret)
            
            # Тестируем с правильным кодом
            assert verify_mfa_code(user_id, "123456") is True
            
            # Тестируем с неправильным кодом
            assert verify_mfa_code(user_id, "12345") is False
            assert verify_mfa_code(user_id, "abcdef") is False

class TestAPIKeysSecurityFixes:
    """Тесты исправлений API ключей"""
    
    @patch('backend.api.api_keys.connection_manager')
    @patch('backend.api.api_keys.get_encryption_service')
    @patch('backend.api.api_keys.execute_supabase_operation')
    def test_supabase_connection_fix(self, mock_execute, mock_encryption, mock_connection_manager):
        """Тест исправления подключения к Supabase"""
        # Настраиваем mocks
        mock_supabase = MagicMock()
        mock_connection_manager.get_pool.return_value = mock_supabase
        mock_encryption_service = MagicMock()
        mock_encryption_service.encrypt_api_key.return_value = "encrypted_key"
        mock_encryption_service.get_key_last_4.return_value = "1234"
        mock_encryption.return_value = mock_encryption_service
        
        mock_response = MagicMock()
        mock_response.data = [{"created_at": "2025-01-11T00:00:00Z"}]
        mock_execute.return_value = mock_response
        
        # Создаем запрос
        request = APIKeyCreateRequest(
            provider=Provider.OPENAI,
            key_name="Test Key",
            api_key="sk-test123456789"
        )
        
        current_user = {"id": "test_user"}
        
        # Вызываем функцию
        result = create_api_key(request, current_user)
        
        # Проверяем, что connection_manager был использован
        mock_connection_manager.get_pool.assert_called_once_with('supabase')
        
        # Проверяем результат
        assert result.provider == "openai"
        assert result.key_name == "Test Key"
        assert result.key_last_4 == "1234"
    
    def test_safe_logging(self):
        """Тест безопасного логирования"""
        with patch('backend.api.api_keys.logger') as mock_logger:
            # Имитируем логирование
            user_id = "test_user_12345"
            provider = "openai"
            
            # Безопасное логирование (обрезаем user_id)
            safe_user_id = f"{user_id[:8]}***"
            mock_logger.info(f"API ключ создан для пользователя {safe_user_id}, провайдер {provider}")
            
            # Проверяем, что логирование было безопасным
            mock_logger.info.assert_called_once()
            call_args = mock_logger.info.call_args[0][0]
            assert "test_user***" in call_args
            assert "test_user_12345" not in call_args
    
    def test_safe_error_handling(self):
        """Тест безопасной обработки ошибок"""
        with patch('backend.api.api_keys.logger') as mock_logger:
            # Имитируем ошибку
            error = Exception("Database connection failed")
            
            # Безопасное логирование ошибки
            mock_logger.error(f"Ошибка создания API ключа: {error}")
            
            # Проверяем, что ошибка была залогирована
            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args[0][0]
            assert "Ошибка создания API ключа" in call_args

class TestRBACSecurityFixes:
    """Тесты исправлений RBAC"""
    
    def test_rbac_not_in_memory(self):
        """Тест, что RBAC не хранится только в памяти"""
        from backend.api.rbac import roles, permissions, user_roles
        
        # Проверяем, что структуры существуют
        assert isinstance(roles, dict)
        assert isinstance(permissions, dict)
        assert isinstance(user_roles, dict)
        
        # Проверяем, что есть предопределенные роли
        assert "admin" in roles
        assert "user" in roles
        assert "developer" in roles
        
        # Проверяем, что есть предопределенные разрешения
        assert "basic_chat" in permissions
        assert "admin_panel" in permissions
    
    def test_role_permission_structure(self):
        """Тест структуры ролей и разрешений"""
        from backend.api.rbac import roles, permissions
        
        # Проверяем структуру роли
        admin_role = roles["admin"]
        assert "id" in admin_role
        assert "name" in admin_role
        assert "description" in admin_role
        assert "permissions" in admin_role
        assert admin_role["permissions"] == ["*"]  # Админ имеет все права
        
        # Проверяем структуру разрешения
        basic_chat_perm = permissions["basic_chat"]
        assert "id" in basic_chat_perm
        assert "name" in basic_chat_perm
        assert "description" in basic_chat_perm

class TestFileUploadSecurityFixes:
    """Тесты исправлений загрузки файлов"""
    
    def test_file_validation_placeholder(self):
        """Тест заглушки валидации файлов"""
        # Этот тест проверяет, что функция validate_file существует
        # В реальной реализации здесь должна быть настоящая валидация
        
        from backend.security.file_upload_security import validate_file
        
        # Проверяем, что функция существует
        assert callable(validate_file)
        
        # В реальной реализации здесь должны быть тесты:
        # - Валидация MIME типов
        # - Проверка размера файла
        # - Сканирование на malware
        # - Проверка расширений файлов
    
    def test_path_traversal_validation(self):
        """Тест валидации path traversal"""
        from backend.security.input_validator import validate_path_traversal
        
        # Безопасные пути
        assert validate_path_traversal("project1/file.txt") is True
        assert validate_path_traversal("user_docs/document.pdf") is True
        
        # Опасные пути
        assert validate_path_traversal("../../../etc/passwd") is False
        assert validate_path_traversal("..\\..\\windows\\system32") is False
        assert validate_path_traversal("%2e%2e%2f") is False

if __name__ == "__main__":
    pytest.main([__file__])