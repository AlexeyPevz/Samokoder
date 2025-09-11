"""
Критические тесты для пробелов в покрытии
P0 тесты для блокировки мёржа до зелёного прогона
"""

import pytest
import time
import jwt
from unittest.mock import patch, MagicMock, Mock
from fastapi.testclient import TestClient
from backend.main import app
import redis
from redis.exceptions import ConnectionError, TimeoutError, MemoryError

client = TestClient(app)

class TestCriticalCoverageGaps:
    """Критические тесты для пробелов в покрытии"""
    
    # === P0 - КРИТИЧЕСКИЕ ТЕСТЫ (БЛОКИРУЮТ МЁРЖ) ===
    
    @pytest.mark.asyncio
    async def test_connection_manager_unavailable(self):
        """P0: Тест недоступности connection manager"""
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
    async def test_connection_manager_timeout(self):
        """P0: Тест таймаута connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для таймаута connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.side_effect = TimeoutError("Connection timeout")
                
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
    async def test_connection_manager_error_handling(self):
        """P0: Тест обработки ошибок connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для ошибки connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.side_effect = Exception("Connection manager error")
                
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
    async def test_redis_connection_failure(self):
        """P0: Тест недоступности Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
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
    async def test_redis_timeout(self):
        """P0: Тест таймаута Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для таймаута Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.side_effect = TimeoutError("Redis timeout")
                
                # Выполняем настройку MFA
                response = client.post("/api/auth/mfa/setup")
                
                # Критерии успеха - должен fallback на in-memory
                assert response.status_code == 200
                data = response.json()
                assert "secret" in data
                assert "qr_code" in data
                assert "backup_codes" in data
    
    @pytest.mark.asyncio
    async def test_redis_memory_exhaustion(self):
        """P0: Тест исчерпания памяти Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для исчерпания памяти Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.side_effect = MemoryError("Redis memory exhausted")
                
                # Выполняем настройку MFA
                response = client.post("/api/auth/mfa/setup")
                
                # Критерии успеха - должен fallback на in-memory
                assert response.status_code == 200
                data = response.json()
                assert "secret" in data
                assert "qr_code" in data
                assert "backup_codes" in data
    
    @pytest.mark.asyncio
    async def test_mfa_ttl_expiration(self):
        """P0: Тест истечения TTL MFA секрета"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для истечения TTL
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.get.return_value = None  # TTL истек
                
                # Выполняем верификацию MFA
                verify_data = {"code": "123456"}
                response = client.post("/api/auth/mfa/verify", json=verify_data)
                
                # Критерии успеха - должен вернуть ошибку
                assert response.status_code == 400
                assert "MFA не настроен" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_jwt_rs256_algorithm_attack(self):
        """P0: Тест атаки RS256 алгоритмом"""
        # Создаем токен с RS256 алгоритмом (атака)
        malicious_token = jwt.encode(
            {"user_id": "test_user", "exp": time.time() + 3600},
            "secret",
            algorithm="RS256"  # Атака algorithm confusion
        )
        
        headers = {"Authorization": f"Bearer {malicious_token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха - должен отклонить токен
        assert response.status_code == 401
        assert "Invalid JWT algorithm" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_jwt_none_algorithm_attack(self):
        """P0: Тест атаки None алгоритмом"""
        # Создаем токен с None алгоритмом (атака)
        malicious_token = jwt.encode(
            {"user_id": "test_user", "exp": time.time() + 3600},
            "secret",
            algorithm="none"  # Атака None algorithm
        )
        
        headers = {"Authorization": f"Bearer {malicious_token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха - должен отклонить токен
        assert response.status_code == 401
        assert "Invalid JWT algorithm" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_jwt_invalid_header(self):
        """P0: Тест невалидного заголовка JWT"""
        # Создаем токен с невалидным заголовком
        malicious_token = "invalid.header.signature"
        
        headers = {"Authorization": f"Bearer {malicious_token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха - должен отклонить токен
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_jwt_malformed_token(self):
        """P0: Тест поврежденного JWT токена"""
        # Создаем поврежденный токен
        malicious_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
        
        headers = {"Authorization": f"Bearer {malicious_token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха - должен отклонить токен
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_jwt_algorithm_confusion(self):
        """P0: Тест confusion атаки на JWT"""
        # Создаем токен с подменой алгоритма в заголовке
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user_id": "test_user", "exp": time.time() + 3600}
        
        # Создаем токен с RS256 в заголовке, но подписываем HS256
        malicious_token = jwt.encode(payload, "secret", algorithm="HS256")
        
        # Подменяем заголовок
        parts = malicious_token.split('.')
        import base64
        import json
        
        # Декодируем и изменяем заголовок
        header_bytes = base64.urlsafe_b64decode(parts[0] + '==')
        header_dict = json.loads(header_bytes)
        header_dict['alg'] = 'RS256'
        
        # Кодируем обратно
        new_header = base64.urlsafe_b64encode(json.dumps(header_dict).encode()).decode().rstrip('=')
        malicious_token = f"{new_header}.{parts[1]}.{parts[2]}"
        
        headers = {"Authorization": f"Bearer {malicious_token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха - должен отклонить токен
        assert response.status_code == 401
        assert "Invalid JWT algorithm" in response.json().get("detail", "")

class TestErrorHandlingCoverage:
    """Тесты для покрытия error handling"""
    
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
                
                # Настраиваем mock для Supabase операции с ошибкой
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.side_effect = Exception("Database connection failed")
                    
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
                    mock_enc_service = MagicMock()
                    mock_enc_service.encrypt_api_key.side_effect = Exception("Encryption failed")
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
                    mock_exec.side_effect = TimeoutError("Network timeout")
                    
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

class TestSecurityBoundaryCoverage:
    """Тесты для покрытия security boundaries"""
    
    @pytest.mark.asyncio
    async def test_sql_injection_attempts(self):
        """P1: Тест попыток SQL injection"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Выполняем создание API ключа с SQL injection в имени
            key_data = {
                "provider": "openai",
                "key_name": "'; DROP TABLE users; --",  # SQL injection
                "api_key": "sk-test1234567890abcdef"
            }
            response = client.post("/api/api-keys/", json=key_data)
            
            # Критерии успеха - должен обработать безопасно
            # Может вернуть 422 (validation error) или 200 (если экранировано)
            assert response.status_code in [200, 422]
    
    @pytest.mark.asyncio
    async def test_xss_attacks(self):
        """P1: Тест XSS атак"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Выполняем создание API ключа с XSS в имени
            key_data = {
                "provider": "openai",
                "key_name": "<script>alert('XSS')</script>",  # XSS
                "api_key": "sk-test1234567890abcdef"
            }
            response = client.post("/api/api-keys/", json=key_data)
            
            # Критерии успеха - должен обработать безопасно
            # Может вернуть 422 (validation error) или 200 (если экранировано)
            assert response.status_code in [200, 422]
    
    @pytest.mark.asyncio
    async def test_csrf_bypass(self):
        """P1: Тест обхода CSRF"""
        # Выполняем POST запрос без CSRF токена
        key_data = {
            "provider": "openai",
            "key_name": "Test Key",
            "api_key": "sk-test1234567890abcdef"
        }
        response = client.post("/api/api-keys/", json=key_data)
        
        # Критерии успеха - должен вернуть 403 (CSRF protection)
        assert response.status_code == 403
        assert "CSRF token missing" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_rate_limiting_bypass(self):
        """P1: Тест обхода rate limiting"""
        # Выполняем множество запросов для проверки rate limiting
        for i in range(100):
            response = client.get("/health")
            
            # Проверяем заголовки rate limiting
            if "X-RateLimit-Remaining" in response.headers:
                remaining = int(response.headers["X-RateLimit-Remaining"])
                if remaining == 0:
                    # Rate limit достигнут
                    assert response.status_code == 429
                    break
            else:
                # Rate limiting не настроен
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_authentication_bypass(self):
        """P1: Тест обхода аутентификации"""
        # Выполняем запрос к защищенному эндпоинту без токена
        response = client.get("/api/auth/user")
        
        # Критерии успеха - должен вернуть 401
        assert response.status_code == 401

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])