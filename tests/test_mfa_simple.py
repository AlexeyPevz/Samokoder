"""
Простые тесты для MFA без сложных зависимостей
"""

import pytest
from unittest.mock import patch, MagicMock

class TestMFASimple:
    """Простые тесты для MFA"""
    
    def test_mfa_functions_exist(self):
        """Проверяем, что функции MFA существуют"""
        from backend.api import mfa
        
        # Проверяем, что все функции существуют
        assert hasattr(mfa, 'store_mfa_secret')
        assert hasattr(mfa, 'get_mfa_secret')
        assert hasattr(mfa, 'delete_mfa_secret')
        assert hasattr(mfa, 'setup_mfa')
        assert hasattr(mfa, 'verify_mfa')
        assert hasattr(mfa, 'disable_mfa')
    
    def test_store_mfa_secret_function(self):
        """Тест функции store_mfa_secret"""
        from backend.api.mfa import store_mfa_secret
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.setex.return_value = True
            
            # Тестируем функцию
            store_mfa_secret("test_user", "test_secret")
            
            # Проверяем, что Redis был вызван
            mock_redis.setex.assert_called_once_with("mfa_secret:test_user", 3600, "test_secret")
    
    def test_get_mfa_secret_function(self):
        """Тест функции get_mfa_secret"""
        from backend.api.mfa import get_mfa_secret
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.get.return_value = b"test_secret"
            
            # Тестируем функцию
            result = get_mfa_secret("test_user")
            
            # Проверяем результат
            assert result == "test_secret"
            mock_redis.get.assert_called_once_with("mfa_secret:test_user")
    
    def test_delete_mfa_secret_function(self):
        """Тест функции delete_mfa_secret"""
        from backend.api.mfa import delete_mfa_secret
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.delete.return_value = 1
            
            # Тестируем функцию
            delete_mfa_secret("test_user")
            
            # Проверяем, что Redis был вызван
            mock_redis.delete.assert_called_once_with("mfa_secret:test_user")
    
    def test_mfa_secret_generation(self):
        """Тест генерации MFA секрета"""
        from backend.api.mfa import setup_mfa
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.setex.return_value = True
            
            # Настраиваем mock для qrcode
            with patch('backend.api.mfa.qrcode') as mock_qr:
                mock_qr.make.return_value = MagicMock()
                
                # Тестируем функцию
                result = setup_mfa("test_user")
                
                # Проверяем результат
                assert "secret" in result
                assert "qr_code" in result
                assert "backup_codes" in result
                assert len(result["backup_codes"]) == 10
    
    def test_mfa_verification_with_pyotp(self):
        """Тест верификации MFA с pyotp"""
        from backend.api.mfa import verify_mfa
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.get.return_value = b"test_secret"
            
            # Настраиваем mock для pyotp
            with patch('pyotp.TOTP') as mock_totp_class:
                mock_totp = MagicMock()
                mock_totp.verify.return_value = True
                mock_totp_class.return_value = mock_totp
                
                # Тестируем функцию
                result = verify_mfa("test_user", "123456")
                
                # Проверяем результат
                assert result["verified"] is True
                assert "MFA код подтвержден" in result["message"]
    
    def test_mfa_verification_invalid_code(self):
        """Тест верификации MFA с невалидным кодом"""
        from backend.api.mfa import verify_mfa
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.get.return_value = b"test_secret"
            
            # Настраиваем mock для pyotp
            with patch('pyotp.TOTP') as mock_totp_class:
                mock_totp = MagicMock()
                mock_totp.verify.return_value = False
                mock_totp_class.return_value = mock_totp
                
                # Тестируем функцию
                result = verify_mfa("test_user", "invalid")
                
                # Проверяем результат
                assert result["verified"] is False
                assert "Неверный MFA код" in result["message"]
    
    def test_mfa_verification_no_secret(self):
        """Тест верификации MFA когда секрет не найден"""
        from backend.api.mfa import verify_mfa
        
        # Настраиваем mock для Redis (секрет не найден)
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.get.return_value = None
            
            # Тестируем функцию
            result = verify_mfa("test_user", "123456")
            
            # Проверяем результат
            assert result["verified"] is False
            assert "MFA не настроен" in result["message"]
    
    def test_mfa_fallback_to_in_memory(self):
        """Тест fallback на in-memory storage"""
        from backend.api.mfa import store_mfa_secret, get_mfa_secret
        
        # Настраиваем mock для недоступности Redis
        with patch('backend.api.mfa.redis_client', None):
            # Настраиваем mock для in-memory storage
            with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                # Тестируем сохранение
                store_mfa_secret("test_user", "test_secret")
                
                # Проверяем, что секрет сохранен в in-memory
                assert "test_user" in mock_secrets
                assert mock_secrets["test_user"] == "test_secret"
                
                # Тестируем получение
                result = get_mfa_secret("test_user")
                assert result == "test_secret"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])