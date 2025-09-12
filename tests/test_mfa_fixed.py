"""
Исправленные тесты для MFA с правильными фикстурами
"""

import pytest
from unittest.mock import patch, MagicMock

class TestMFAFixed:
    """Исправленные тесты для MFA"""
    
    def test_setup_mfa_success(self, client, mock_redis_client, mock_current_user):
        """Тест успешной настройки MFA"""
        # Выполняем настройку MFA
        response = client.post("/api/auth/mfa/setup")
        
        # Критерии успеха
        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "qr_code" in data
        assert "backup_codes" in data
        assert len(data["backup_codes"]) == 10
        
        # Проверяем, что секрет сохранен в Redis
        mock_redis_client.setex.assert_called_once()
        call_args = mock_redis_client.setex.call_args
        assert call_args[0][0] == "mfa_secret:test_user_123"
        assert call_args[0][1] == 3600  # TTL
    
    def test_verify_mfa_success(self, client, mock_redis_client, mock_current_user):
        """Тест успешной верификации MFA"""
        # Настраиваем mock для pyotp (импортируется внутри функции)
        with patch('pyotp.TOTP') as mock_totp_class:
            mock_totp = MagicMock()
            mock_totp.verify.return_value = True
            mock_totp_class.return_value = mock_totp
            
            # Выполняем верификацию MFA
            verify_data = {"code": "123456"}
            response = client.post("/api/auth/mfa/verify", json=verify_data)
            
            # Критерии успеха
            assert response.status_code == 200
            data = response.json()
            assert data["verified"] is True
            assert "MFA код подтвержден" in data["message"]
            
            # Проверяем, что секрет получен из Redis
            mock_redis_client.get.assert_called_with("mfa_secret:test_user_123")
    
    def test_verify_mfa_invalid_code(self, client, mock_redis_client, mock_current_user):
        """Тест верификации MFA с невалидным кодом"""
        # Настраиваем mock для pyotp (импортируется внутри функции)
        with patch('pyotp.TOTP') as mock_totp_class:
            mock_totp = MagicMock()
            mock_totp.verify.return_value = False
            mock_totp_class.return_value = mock_totp
            
            # Выполняем верификацию MFA с невалидным кодом
            verify_data = {"code": "invalid"}
            response = client.post("/api/auth/mfa/verify", json=verify_data)
            
            # Критерии успеха
            assert response.status_code == 200
            data = response.json()
            assert data["verified"] is False
            assert "Неверный MFA код" in data["message"]
    
    def test_verify_mfa_not_setup(self, client, mock_redis_client, mock_current_user):
        """Тест верификации MFA когда не настроен"""
        # Настраиваем mock для Redis (секрет не найден)
        mock_redis_client.get.return_value = None
        
        # Выполняем верификацию MFA
        verify_data = {"code": "123456"}
        response = client.post("/api/auth/mfa/verify", json=verify_data)
        
        # Критерии успеха - должен вернуть 400
        assert response.status_code == 400
        assert "MFA не настроен" in response.json()["detail"]
    
    def test_disable_mfa_success(self, client, mock_redis_client, mock_current_user):
        """Тест успешного отключения MFA"""
        # Выполняем отключение MFA
        response = client.delete("/api/auth/mfa/disable")
        
        # Критерии успеха
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["message"] == "MFA отключен"
        
        # Проверяем, что секрет удален из Redis
        mock_redis_client.delete.assert_called_with("mfa_secret:test_user_123")
    
    def test_disable_mfa_redis_failure(self, client, mock_redis_client, mock_current_user):
        """Тест отключения MFA при ошибке Redis"""
        # Настраиваем mock для Redis с ошибкой
        mock_redis_client.delete.side_effect = Exception("Redis connection failed")
        
        # Выполняем отключение MFA
        response = client.delete("/api/auth/mfa/disable")
        
        # Критерии успеха - должен вернуть ошибку 500
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data
        assert "Redis connection failed" in data["detail"]
    
    def test_disable_mfa_redis_unavailable(self, client, mock_current_user):
        """Тест отключения MFA при недоступности Redis"""
        # Настраиваем mock для недоступности Redis
        with patch('backend.api.mfa.redis_client', None):
            # Выполняем отключение MFA
            response = client.delete("/api/auth/mfa/disable")
            
            # Критерии успеха - должен fallback на in-memory
            assert response.status_code == 200
            data = response.json()
            assert "message" in data
            assert data["message"] == "MFA отключен"
    
    def test_mfa_fallback_to_in_memory(self, client, mock_current_user):
        """Тест fallback на in-memory storage"""
        # Настраиваем mock для недоступности Redis
        with patch('backend.api.mfa.redis_client', None):
            # Настраиваем mock для in-memory storage
            with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                # Выполняем настройку MFA
                response = client.post("/api/auth/mfa/setup")
                
                # Критерии успеха
                assert response.status_code == 200
                data = response.json()
                assert "secret" in data
                assert "qr_code" in data
                assert "backup_codes" in data
                
                # Проверяем, что секрет сохранен в in-memory
                assert "test_user_123" in mock_secrets

if __name__ == "__main__":
    pytest.main([__file__, "-v"])