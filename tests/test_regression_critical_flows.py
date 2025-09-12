"""
Регрессионные тесты для критических пользовательских потоков
P0/P1 тесты для блокировки мёржа до зелёного прогона
"""

import pytest
import json
import time
import jwt
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

class TestRegressionCriticalFlows:
    """Регрессионные тесты критических пользовательских потоков"""
    
    # === P0 - КРИТИЧЕСКИЕ ТЕСТЫ (БЛОКИРУЮТ МЁРЖ) ===
    
    @pytest.mark.asyncio
    async def test_jwt_token_validation_regression(self):
        """P0: Регрессионный тест валидации JWT токенов"""
        # Шаг 1: Логин
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        
        with patch('backend.main.supabase_manager') as mock_supabase:
            # Настраиваем mock для успешного логина
            mock_user = MagicMock()
            mock_user.id = "test_user_123"
            mock_user.email = "test@example.com"
            mock_user.created_at = "2025-01-11T00:00:00Z"
            mock_user.updated_at = "2025-01-11T00:00:00Z"
            mock_user.user_metadata = {"full_name": "Test User"}
            
            mock_session = MagicMock()
            mock_session.access_token = "valid_jwt_token"
            
            mock_response = MagicMock()
            mock_response.user = mock_user
            mock_response.session = mock_session
            
            mock_client = MagicMock()
            mock_client.auth.sign_in_with_password.return_value = mock_response
            mock_supabase.get_client.return_value = mock_client
            
            # Выполняем логин
            response = client.post("/api/auth/login", json=login_data)
            assert response.status_code == 200
            
            token = response.json()["access_token"]
            
            # Шаг 2: Проверяем доступ к защищенному эндпоинту
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/api/auth/user", headers=headers)
            
            # Критерии успеха
            assert response.status_code == 200
            assert "user" in response.json()
            
            # Шаг 3: Проверяем отклонение невалидного токена
            invalid_headers = {"Authorization": "Bearer invalid_token"}
            response = client.get("/api/auth/user", headers=invalid_headers)
            assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_jwt_algorithm_validation_regression(self):
        """P0: Регрессионный тест валидации алгоритма JWT"""
        # Создаем токен с неправильным алгоритмом
        invalid_token = jwt.encode(
            {"user_id": "test_user", "exp": time.time() + 3600},
            "secret",
            algorithm="RS256"  # Неправильный алгоритм
        )
        
        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха
        assert response.status_code == 401
        assert "Invalid JWT algorithm" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_mfa_setup_redis_storage_regression(self):
        """P0: Регрессионный тест настройки MFA с Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.return_value = True
                
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
                mock_redis.setex.assert_called_once()
                call_args = mock_redis.setex.call_args
                assert call_args[0][0] == "mfa_secret:test_user_123"
                assert call_args[0][2] == 3600  # TTL 1 час
    
    @pytest.mark.asyncio
    async def test_mfa_verification_totp_regression(self):
        """P0: Регрессионный тест верификации MFA с TOTP"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.get.return_value = "test_mfa_secret"
                
                # Настраиваем mock для pyotp
                with patch('backend.api.mfa.pyotp') as mock_pyotp:
                    mock_totp = MagicMock()
                    mock_totp.verify.return_value = True
                    mock_pyotp.TOTP.return_value = mock_totp
                    
                    # Выполняем верификацию MFA
                    verify_data = {"code": "123456"}
                    response = client.post("/api/auth/mfa/verify", json=verify_data)
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert data["verified"] is True
                    assert "MFA код подтвержден" in data["message"]
                    
                    # Проверяем вызов TOTP верификации
                    mock_totp.verify.assert_called()
    
    @pytest.mark.asyncio
    async def test_api_key_creation_connection_manager_regression(self):
        """P0: Регрессионный тест создания API ключей с connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=[{"created_at": "2025-01-11T00:00:00Z"}])
                    
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
                        
                        # Критерии успеха
                        assert response.status_code == 200
                        data = response.json()
                        assert data["provider"] == "openai"
                        assert data["key_name"] == "Test Key"
                        assert data["key_last_4"] == "1234"
                        assert data["is_active"] is True
                        
                        # Проверяем использование connection manager
                        mock_conn_mgr.get_pool.assert_called_with('supabase')
    
    @pytest.mark.asyncio
    async def test_api_key_retrieval_connection_manager_regression(self):
        """P0: Регрессионный тест получения API ключей с connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=[
                        {
                            "id": "key_123",
                            "provider": "openai",
                            "key_name": "Test Key",
                            "key_last_4": "1234",
                            "is_active": True,
                            "created_at": "2025-01-11T00:00:00Z"
                        }
                    ])
                    
                    # Выполняем получение API ключей
                    response = client.get("/api/api-keys/")
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert "keys" in data
                    assert "total_count" in data
                    assert len(data["keys"]) == 1
                    assert data["keys"][0]["provider"] == "openai"
                    
                    # Проверяем использование connection manager
                    mock_conn_mgr.get_pool.assert_called_with('supabase')
    
    # === P1 - ВАЖНЫЕ ТЕСТЫ (РЕКОМЕНДУЕТСЯ ПРОЙТИ) ===
    
    @pytest.mark.asyncio
    async def test_mfa_fallback_in_memory_regression(self):
        """P1: Регрессионный тест fallback на in-memory хранилище"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности Redis
            with patch('backend.api.mfa.redis_client', None):
                # Выполняем настройку MFA
                response = client.post("/api/auth/mfa/setup")
                
                # Критерии успеха
                assert response.status_code == 200
                data = response.json()
                assert "secret" in data
                assert "qr_code" in data
                assert "backup_codes" in data
    
    @pytest.mark.asyncio
    async def test_api_key_logging_security_regression(self):
        """P1: Регрессионный тест безопасности логирования API ключей"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123456789", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=[{"created_at": "2025-01-11T00:00:00Z"}])
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Настраиваем mock для логгера
                        with patch('backend.api.api_keys.logger') as mock_logger:
                            # Выполняем создание API ключа
                            key_data = {
                                "provider": "openai",
                                "key_name": "Test Key",
                                "api_key": "sk-test1234567890abcdef"
                            }
                            response = client.post("/api/api-keys/", json=key_data)
                            
                            # Критерии успеха
                            assert response.status_code == 200
                            
                            # Проверяем, что user_id замаскирован в логах
                            mock_logger.info.assert_called()
                            log_calls = mock_logger.info.call_args_list
                            for call in log_calls:
                                log_message = str(call)
                                if "test_user_123456789" in log_message:
                                    pytest.fail("Full user_id found in logs - security issue!")
                                if "test_user_123***" in log_message:
                                    break  # Правильно замаскирован
    
    @pytest.mark.asyncio
    async def test_end_to_end_authentication_flow_regression(self):
        """P1: Регрессионный тест полного потока аутентификации"""
        # Шаг 1: Регистрация
        register_data = {
            "email": "newuser@example.com",
            "password": "newpassword123",
            "full_name": "New User"
        }
        
        with patch('backend.main.supabase_manager') as mock_supabase:
            # Настраиваем mock для регистрации
            mock_user = MagicMock()
            mock_user.id = "new_user_123"
            
            mock_response = MagicMock()
            mock_response.user = mock_user
            mock_supabase.get_client.return_value.auth.sign_up.return_value = mock_response
            
            response = client.post("/api/auth/register", json=register_data)
            assert response.status_code == 201
            
            # Шаг 2: Логин
            login_data = {
                "email": "newuser@example.com",
                "password": "newpassword123"
            }
            
            # Настраиваем mock для логина
            mock_user.email = "newuser@example.com"
            mock_user.created_at = "2025-01-11T00:00:00Z"
            mock_user.updated_at = "2025-01-11T00:00:00Z"
            mock_user.user_metadata = {"full_name": "New User"}
            
            mock_session = MagicMock()
            mock_session.access_token = "valid_jwt_token"
            
            mock_login_response = MagicMock()
            mock_login_response.user = mock_user
            mock_login_response.session = mock_session
            
            mock_supabase.get_client.return_value.auth.sign_in_with_password.return_value = mock_login_response
            
            response = client.post("/api/auth/login", json=login_data)
            assert response.status_code == 200
            
            token = response.json()["access_token"]
            
            # Шаг 3: Настройка MFA
            with patch('backend.auth.dependencies.get_current_user') as mock_user_dep:
                mock_user_dep.return_value = {"id": "new_user_123", "email": "newuser@example.com"}
                
                with patch('backend.api.mfa.redis_client') as mock_redis:
                    mock_redis.setex.return_value = True
                    
                    response = client.post("/api/auth/mfa/setup")
                    assert response.status_code == 200
                    
                    mfa_data = response.json()
                    assert "secret" in mfa_data
                    assert "qr_code" in mfa_data
                    assert "backup_codes" in mfa_data
                    
                    # Шаг 4: Верификация MFA
                    with patch('backend.api.mfa.pyotp') as mock_pyotp:
                        mock_totp = MagicMock()
                        mock_totp.verify.return_value = True
                        mock_pyotp.TOTP.return_value = mock_totp
                        
                        verify_data = {"code": "123456"}
                        response = client.post("/api/auth/mfa/verify", json=verify_data)
                        assert response.status_code == 200
                        assert response.json()["verified"] is True
                        
                        # Шаг 5: Доступ к защищенным ресурсам
                        headers = {"Authorization": f"Bearer {token}"}
                        response = client.get("/api/auth/user", headers=headers)
                        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_api_keys_management_flow_regression(self):
        """P1: Регрессионный тест полного потока управления API ключами"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операций
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=[{"created_at": "2025-01-11T00:00:00Z"}])
                    
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Шаг 1: Создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        assert response.status_code == 200
                        
                        created_key = response.json()
                        key_id = created_key["id"]
                        
                        # Шаг 2: Получение списка ключей
                        mock_exec.return_value = MagicMock(data=[created_key])
                        response = client.get("/api/api-keys/")
                        assert response.status_code == 200
                        assert len(response.json()["keys"]) == 1
                        
                        # Шаг 3: Получение конкретного ключа
                        response = client.get(f"/api/api-keys/{key_id}")
                        assert response.status_code == 200
                        assert response.json()["id"] == key_id
                        
                        # Шаг 4: Переключение статуса ключа
                        response = client.put(f"/api/api-keys/{key_id}/toggle")
                        assert response.status_code == 200
                        assert response.json()["is_active"] is False
                        
                        # Шаг 5: Удаление ключа
                        response = client.delete(f"/api/api-keys/{key_id}")
                        assert response.status_code == 200
                        assert "deleted" in response.json()["message"]

class TestRegressionEdgeCases:
    """Регрессионные тесты для граничных случаев"""
    
    @pytest.mark.asyncio
    async def test_connection_manager_failure_regression(self):
        """P1: Регрессионный тест при недоступности connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.return_value = None
                
                # Выполняем создание API ключа
                key_data = {
                    "provider": "openai",
                    "key_name": "Test Key",
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен вернуть 503
                assert response.status_code == 503
                assert "Supabase недоступен" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_redis_connection_failure_regression(self):
        """P1: Регрессионный тест при недоступности Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.side_effect = Exception("Redis connection failed")
                
                # Выполняем настройку MFA
                response = client.post("/api/auth/mfa/setup")
                
                # Критерии успеха - должен fallback на in-memory
                assert response.status_code == 200
                data = response.json()
                assert "secret" in data
                assert "qr_code" in data
                assert "backup_codes" in data
    
    @pytest.mark.asyncio
    async def test_jwt_token_expiration_regression(self):
        """P1: Регрессионный тест истечения JWT токена"""
        # Создаем истекший токен
        expired_token = jwt.encode(
            {"user_id": "test_user", "exp": time.time() - 3600},  # Истек час назад
            "secret",
            algorithm="HS256"
        )
        
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха
        assert response.status_code == 401
        assert "expired" in response.json().get("detail", "").lower()
    
    @pytest.mark.asyncio
    async def test_mfa_invalid_code_regression(self):
        """P1: Регрессионный тест невалидного MFA кода"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.get.return_value = "test_mfa_secret"
                
                # Настраиваем mock для pyotp
                with patch('backend.api.mfa.pyotp') as mock_pyotp:
                    mock_totp = MagicMock()
                    mock_totp.verify.return_value = False  # Невалидный код
                    mock_pyotp.TOTP.return_value = mock_totp
                    
                    # Выполняем верификацию MFA с невалидным кодом
                    verify_data = {"code": "000000"}
                    response = client.post("/api/auth/mfa/verify", json=verify_data)
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert data["verified"] is False
                    assert "Неверный MFA код" in data["message"]

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])