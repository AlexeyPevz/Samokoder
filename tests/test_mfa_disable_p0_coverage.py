"""
P0 тесты для MFA disable функции - критические пробелы в покрытии
Блокируют мёрж до зелёного прогона
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

class TestMFADisableP0Coverage:
    """P0 тесты для критических пробелов в MFA disable"""
    
    # === P0 - КРИТИЧЕСКИЕ ТЕСТЫ (БЛОКИРУЮТ МЁРЖ) ===
    
    @pytest.mark.asyncio
    async def test_disable_mfa_success(self):
        """P0: Тест успешного отключения MFA"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для delete_mfa_secret
            with patch('backend.api.mfa.delete_mfa_secret') as mock_delete:
                mock_delete.return_value = None
                
                # Выполняем отключение MFA
                response = client.delete("/api/auth/mfa/disable")
                
                # Критерии успеха
                assert response.status_code == 200
                data = response.json()
                assert "message" in data
                assert data["message"] == "MFA отключен"
                
                # Проверяем, что delete_mfa_secret был вызван
                mock_delete.assert_called_once_with("test_user_123")
    
    @pytest.mark.asyncio
    async def test_disable_mfa_redis_success(self):
        """P0: Тест успешного отключения MFA с Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.delete.return_value = 1  # Успешное удаление
                
                # Выполняем отключение MFA
                response = client.delete("/api/auth/mfa/disable")
                
                # Критерии успеха
                assert response.status_code == 200
                data = response.json()
                assert "message" in data
                assert data["message"] == "MFA отключен"
                
                # Проверяем, что Redis delete был вызван
                mock_redis.delete.assert_called_once_with("mfa_secret:test_user_123")
    
    @pytest.mark.asyncio
    async def test_disable_mfa_redis_failure_fallback(self):
        """P0: Тест отключения MFA при ошибке Redis с fallback на in-memory"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis с ошибкой
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.delete.side_effect = Exception("Redis connection failed")
                
                # Настраиваем mock для in-memory fallback
                with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                    # Выполняем отключение MFA
                    response = client.delete("/api/auth/mfa/disable")
                    
                    # Критерии успеха - должен fallback на in-memory
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert data["message"] == "MFA отключен"
    
    @pytest.mark.asyncio
    async def test_disable_mfa_redis_unavailable_fallback(self):
        """P0: Тест отключения MFA при недоступности Redis с fallback на in-memory"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности Redis
            with patch('backend.api.mfa.redis_client', None):
                # Настраиваем mock для in-memory fallback
                with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                    # Выполняем отключение MFA
                    response = client.delete("/api/auth/mfa/disable")
                    
                    # Критерии успеха - должен fallback на in-memory
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert data["message"] == "MFA отключен"
    
    @pytest.mark.asyncio
    async def test_disable_mfa_in_memory_success(self):
        """P0: Тест успешного отключения MFA в in-memory режиме"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности Redis
            with patch('backend.api.mfa.redis_client', None):
                # Настраиваем mock для in-memory storage
                with patch('backend.api.mfa.mfa_secrets', {"test_user_123": "secret_value"}) as mock_secrets:
                    # Выполняем отключение MFA
                    response = client.delete("/api/auth/mfa/disable")
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert data["message"] == "MFA отключен"
                    
                    # Проверяем, что секрет был удален из in-memory storage
                    assert "test_user_123" not in mock_secrets
    
    @pytest.mark.asyncio
    async def test_disable_mfa_in_memory_not_found(self):
        """P0: Тест отключения MFA когда секрет не найден в in-memory"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности Redis
            with patch('backend.api.mfa.redis_client', None):
                # Настраиваем mock для пустого in-memory storage
                with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                    # Выполняем отключение MFA
                    response = client.delete("/api/auth/mfa/disable")
                    
                    # Критерии успеха - должен работать даже если секрет не найден
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert data["message"] == "MFA отключен"
    
    @pytest.mark.asyncio
    async def test_disable_mfa_redis_key_not_found(self):
        """P0: Тест отключения MFA когда ключ не найден в Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.delete.return_value = 0  # Ключ не найден
                
                # Выполняем отключение MFA
                response = client.delete("/api/auth/mfa/disable")
                
                # Критерии успеха - должен работать даже если ключ не найден
                assert response.status_code == 200
                data = response.json()
                assert "message" in data
                assert data["message"] == "MFA отключен"
                
                # Проверяем, что Redis delete был вызван
                mock_redis.delete.assert_called_once_with("mfa_secret:test_user_123")
    
    @pytest.mark.asyncio
    async def test_disable_mfa_redis_timeout(self):
        """P0: Тест отключения MFA при таймауте Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis с таймаутом
            with patch('backend.api.mfa.redis_client') as mock_redis:
                from redis.exceptions import TimeoutError
                mock_redis.delete.side_effect = TimeoutError("Redis timeout")
                
                # Настраиваем mock для in-memory fallback
                with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                    # Выполняем отключение MFA
                    response = client.delete("/api/auth/mfa/disable")
                    
                    # Критерии успеха - должен fallback на in-memory
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert data["message"] == "MFA отключен"
    
    @pytest.mark.asyncio
    async def test_disable_mfa_redis_connection_error(self):
        """P0: Тест отключения MFA при ошибке подключения к Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis с ошибкой подключения
            with patch('backend.api.mfa.redis_client') as mock_redis:
                from redis.exceptions import ConnectionError
                mock_redis.delete.side_effect = ConnectionError("Redis connection failed")
                
                # Настраиваем mock для in-memory fallback
                with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                    # Выполняем отключение MFA
                    response = client.delete("/api/auth/mfa/disable")
                    
                    # Критерии успеха - должен fallback на in-memory
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert data["message"] == "MFA отключен"
    
    @pytest.mark.asyncio
    async def test_disable_mfa_redis_memory_error(self):
        """P0: Тест отключения MFA при ошибке памяти Redis"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis с ошибкой памяти
            with patch('backend.api.mfa.redis_client') as mock_redis:
                from redis.exceptions import MemoryError
                mock_redis.delete.side_effect = MemoryError("Redis memory exhausted")
                
                # Настраиваем mock для in-memory fallback
                with patch('backend.api.mfa.mfa_secrets', {}) as mock_secrets:
                    # Выполняем отключение MFA
                    response = client.delete("/api/auth/mfa/disable")
                    
                    # Критерии успеха - должен fallback на in-memory
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert data["message"] == "MFA отключен"
    
    @pytest.mark.asyncio
    async def test_disable_mfa_general_exception(self):
        """P0: Тест отключения MFA при общей ошибке"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для delete_mfa_secret с ошибкой
            with patch('backend.api.mfa.delete_mfa_secret') as mock_delete:
                mock_delete.side_effect = Exception("Unexpected error")
                
                # Выполняем отключение MFA
                response = client.delete("/api/auth/mfa/disable")
                
                # Критерии успеха - должен вернуть 500
                assert response.status_code == 500
                data = response.json()
                assert "detail" in data
                assert "Ошибка отключения MFA" in data["detail"]
                assert "Unexpected error" in data["detail"]
    
    @pytest.mark.asyncio
    async def test_disable_mfa_unauthorized(self):
        """P0: Тест отключения MFA без аутентификации"""
        # Не настраиваем mock для аутентификации
        
        # Выполняем отключение MFA без токена
        response = client.delete("/api/auth/mfa/disable")
        
        # Критерии успеха - должен вернуть 401
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_disable_mfa_csrf_protection(self):
        """P0: Тест отключения MFA с CSRF защитой"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Выполняем отключение MFA без CSRF токена
            response = client.delete("/api/auth/mfa/disable")
            
            # Критерии успеха - должен вернуть 403 (CSRF protection)
            assert response.status_code == 403
            assert "CSRF token missing" in response.json()["detail"]

class TestMFADisableIntegration:
    """P0 интеграционные тесты для MFA disable"""
    
    @pytest.mark.asyncio
    async def test_disable_mfa_after_setup(self):
        """P0: Тест отключения MFA после настройки"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Сначала настраиваем MFA
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.return_value = True
                
                setup_response = client.post("/api/auth/mfa/setup")
                assert setup_response.status_code == 200
                
                # Затем отключаем MFA
                mock_redis.delete.return_value = 1
                
                disable_response = client.delete("/api/auth/mfa/disable")
                assert disable_response.status_code == 200
                
                data = disable_response.json()
                assert "message" in data
                assert data["message"] == "MFA отключен"
                
                # Проверяем, что Redis операции были вызваны
                mock_redis.setex.assert_called_once()
                mock_redis.delete.assert_called_once_with("mfa_secret:test_user_123")
    
    @pytest.mark.asyncio
    async def test_disable_mfa_multiple_times(self):
        """P0: Тест многократного отключения MFA"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.delete.return_value = 0  # Ключ не найден при повторном отключении
                
                # Отключаем MFA первый раз
                response1 = client.delete("/api/auth/mfa/disable")
                assert response1.status_code == 200
                
                # Отключаем MFA второй раз
                response2 = client.delete("/api/auth/mfa/disable")
                assert response2.status_code == 200
                
                # Проверяем, что Redis delete был вызван дважды
                assert mock_redis.delete.call_count == 2
                mock_redis.delete.assert_any_call("mfa_secret:test_user_123")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])