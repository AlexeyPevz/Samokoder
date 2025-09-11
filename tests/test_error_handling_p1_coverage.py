"""
P1 тесты для error handling сценариев - важные пробелы в покрытии
Рекомендуются для улучшения качества
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

class TestErrorHandlingP1Coverage:
    """P1 тесты для error handling сценариев"""
    
    # === P1 - ВАЖНЫЕ ТЕСТЫ (РЕКОМЕНДУЮТСЯ) ===
    
    @pytest.mark.asyncio
    async def test_database_connection_errors(self):
        """P1: Тест ошибок подключения к БД"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции с ошибкой подключения
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    from backend.core.exceptions import DatabaseError
                    mock_exec.side_effect = DatabaseError("Database connection failed")
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха - должен вернуть 503
                        assert response.status_code == 503
                        assert "Database service unavailable" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_network_timeouts(self):
        """P1: Тест сетевых таймаутов"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции с таймаутом
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    import asyncio
                    mock_exec.side_effect = asyncio.TimeoutError("Network timeout")
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха - должен вернуть 500
                        assert response.status_code == 500
                        assert "Ошибка создания API ключа" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_memory_exhaustion(self):
        """P1: Тест исчерпания памяти"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции с ошибкой памяти
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.side_effect = MemoryError("Memory exhausted")
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха - должен вернуть 500
                        assert response.status_code == 500
                        assert "Ошибка создания API ключа" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_encryption_service_errors(self):
        """P1: Тест ошибок encryption service"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для encryption service с ошибкой
                with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                    from backend.core.exceptions import EncryptionError
                    mock_enc_service = MagicMock()
                    mock_enc_service.encrypt_api_key.side_effect = EncryptionError("Encryption failed")
                    mock_enc.return_value = mock_enc_service
                    
                    # Выполняем создание API ключа
                    key_data = {
                        "provider": "openai",
                        "key_name": "Test Key",
                        "api_key": "sk-test1234567890abcdef"
                    }
                    response = client.post("/api/api-keys/", json=key_data)
                    
                    # Критерии успеха - должен вернуть 500
                    assert response.status_code == 500
                    assert "Encryption service error" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_validation_errors(self):
        """P1: Тест ошибок валидации"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Выполняем создание API ключа с невалидными данными
            key_data = {
                "provider": "invalid_provider",  # Невалидный провайдер
                "key_name": "",  # Пустое имя
                "api_key": "short"  # Слишком короткий ключ
            }
            response = client.post("/api/api-keys/", json=key_data)
            
            # Критерии успеха - должен вернуть 422 (validation error)
            assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_concurrent_access_errors(self):
        """P1: Тест ошибок при конкурентном доступе"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции с ошибкой конкурентного доступа
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.side_effect = Exception("Concurrent access violation")
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха - должен вернуть 500
                        assert response.status_code == 500
                        assert "Ошибка создания API ключа" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_disk_space_exhaustion(self):
        """P1: Тест исчерпания дискового пространства"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции с ошибкой дискового пространства
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.side_effect = OSError("No space left on device")
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха - должен вернуть 500
                        assert response.status_code == 500
                        assert "Ошибка создания API ключа" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_database_deadlock(self):
        """P1: Тест deadlock в базе данных"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции с deadlock
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.side_effect = Exception("Database deadlock detected")
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха - должен вернуть 500
                        assert response.status_code == 500
                        assert "Ошибка создания API ключа" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_connection_pool_exhaustion(self):
        """P1: Тест исчерпания connection pool"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager с исчерпанным pool
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.side_effect = Exception("Connection pool exhausted")
                
                # Выполняем создание API ключа
                key_data = {
                    "provider": "openai",
                    "key_name": "Test Key",
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен вернуть 500
                assert response.status_code == 500
                assert "Ошибка создания API ключа" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_service_unavailable_errors(self):
        """P1: Тест недоступности сервисов"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции с недоступностью сервиса
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.side_effect = Exception("Service temporarily unavailable")
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха - должен вернуть 500
                        assert response.status_code == 500
                        assert "Ошибка создания API ключа" in response.json()["detail"]

class TestErrorHandlingMFA:
    """P1 тесты для error handling в MFA"""
    
    @pytest.mark.asyncio
    async def test_mfa_setup_redis_connection_error(self):
        """P1: Тест ошибки подключения к Redis при настройке MFA"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis с ошибкой подключения
            with patch('backend.api.mfa.redis_client') as mock_redis:
                from redis.exceptions import ConnectionError
                mock_redis.setex.side_effect = ConnectionError("Redis connection failed")
                
                # Выполняем настройку MFA
                response = client.post("/api/auth/mfa/setup")
                
                # Критерии успеха - должен fallback на in-memory
                assert response.status_code == 200
                data = response.json()
                assert "secret" in data
                assert "qr_code" in data
                assert "backup_codes" in data
    
    @pytest.mark.asyncio
    async def test_mfa_verify_invalid_code_format(self):
        """P1: Тест верификации MFA с невалидным форматом кода"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.get.return_value = b"test_secret"
                
                # Выполняем верификацию MFA с невалидным кодом
                verify_data = {"code": "invalid_code"}
                response = client.post("/api/auth/mfa/verify", json=verify_data)
                
                # Критерии успеха - должен вернуть False
                assert response.status_code == 200
                data = response.json()
                assert data["verified"] is False
                assert "Неверный MFA код" in data["message"]
    
    @pytest.mark.asyncio
    async def test_mfa_verify_expired_code(self):
        """P1: Тест верификации MFA с истекшим кодом"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.get.return_value = b"test_secret"
                
                # Настраиваем mock для pyotp с истекшим кодом
                with patch('backend.api.mfa.pyotp') as mock_pyotp:
                    mock_totp = MagicMock()
                    mock_totp.verify.return_value = False  # Код истек
                    mock_pyotp.TOTP.return_value = mock_totp
                    
                    # Выполняем верификацию MFA с истекшим кодом
                    verify_data = {"code": "123456"}
                    response = client.post("/api/auth/mfa/verify", json=verify_data)
                    
                    # Критерии успеха - должен вернуть False
                    assert response.status_code == 200
                    data = response.json()
                    assert data["verified"] is False
                    assert "Неверный MFA код" in data["message"]

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])