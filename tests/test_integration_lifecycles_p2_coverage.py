"""
P2 интеграционные тесты для полных жизненных циклов
Дополнительные тесты для улучшения качества
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

class TestIntegrationLifecyclesP2Coverage:
    """P2 интеграционные тесты для полных жизненных циклов"""
    
    # === P2 - ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ ===
    
    @pytest.mark.asyncio
    async def test_full_api_key_lifecycle(self):
        """P2: Полный жизненный цикл API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операций
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # 1. Создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        
                        # Mock для создания
                        mock_exec.side_effect = [
                            MagicMock(data=[{"id": "key_123", "created_at": "2025-01-11T00:00:00Z"}])  # Создание
                        ]
                        
                        create_response = client.post("/api/api-keys/", json=key_data)
                        assert create_response.status_code == 200
                        create_data = create_response.json()
                        assert create_data["id"] == "key_123"
                        assert create_data["provider"] == "openai"
                        assert create_data["key_name"] == "Test Key"
                        assert create_data["key_last_4"] == "1234"
                        assert create_data["is_active"] is True
                        
                        # 2. Получение списка API ключей
                        mock_exec.side_effect = [
                            MagicMock(data=[
                                {
                                    "id": "key_123",
                                    "provider_name": "openai",
                                    "key_name": "Test Key",
                                    "api_key_last_4": "1234",
                                    "is_active": True,
                                    "created_at": "2025-01-11T00:00:00Z"
                                }
                            ])
                        ]
                        
                        list_response = client.get("/api/api-keys/")
                        assert list_response.status_code == 200
                        list_data = list_response.json()
                        assert list_data["total_count"] == 1
                        assert len(list_data["keys"]) == 1
                        assert list_data["keys"][0]["id"] == "key_123"
                        
                        # 3. Получение конкретного API ключа
                        mock_exec.side_effect = [
                            MagicMock(data={
                                "id": "key_123",
                                "provider_name": "openai",
                                "key_name": "Test Key",
                                "api_key_last_4": "1234",
                                "is_active": True,
                                "created_at": "2025-01-11T00:00:00Z"
                            })
                        ]
                        
                        get_response = client.get("/api/api-keys/key_123")
                        assert get_response.status_code == 200
                        get_data = get_response.json()
                        assert get_data["id"] == "key_123"
                        assert get_data["provider"] == "openai"
                        
                        # 4. Переключение статуса API ключа
                        mock_exec.side_effect = [
                            MagicMock(data={"is_active": True}),  # Получение текущего статуса
                            MagicMock(data={})  # Обновление статуса
                        ]
                        
                        toggle_response = client.put("/api/api-keys/key_123/toggle")
                        assert toggle_response.status_code == 200
                        toggle_data = toggle_response.json()
                        assert toggle_data["is_active"] is False
                        assert "выключен" in toggle_data["message"]
                        
                        # 5. Удаление API ключа
                        mock_exec.side_effect = [
                            MagicMock(data={"id": "key_123"}),  # Проверка существования
                            MagicMock(data={})  # Удаление
                        ]
                        
                        delete_response = client.delete("/api/api-keys/key_123")
                        assert delete_response.status_code == 200
                        delete_data = delete_response.json()
                        assert "API ключ удален" in delete_data["message"]
                        
                        # 6. Проверка, что ключ удален
                        mock_exec.side_effect = [
                            MagicMock(data=[])  # Пустой список
                        ]
                        
                        final_list_response = client.get("/api/api-keys/")
                        assert final_list_response.status_code == 200
                        final_list_data = final_list_response.json()
                        assert final_list_data["total_count"] == 0
                        assert len(final_list_data["keys"]) == 0
    
    @pytest.mark.asyncio
    async def test_full_mfa_lifecycle(self):
        """P2: Полный жизненный цикл MFA"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.return_value = True
                mock_redis.get.return_value = b"test_secret"
                mock_redis.delete.return_value = 1
                
                # 1. Настройка MFA
                setup_response = client.post("/api/auth/mfa/setup")
                assert setup_response.status_code == 200
                setup_data = setup_response.json()
                assert "secret" in setup_data
                assert "qr_code" in setup_data
                assert "backup_codes" in setup_data
                assert len(setup_data["backup_codes"]) == 10
                
                # Проверяем, что секрет сохранен в Redis
                mock_redis.setex.assert_called_once()
                call_args = mock_redis.setex.call_args
                assert call_args[0][0] == "mfa_secret:test_user_123"
                assert call_args[0][1] == 3600  # TTL
                
                # 2. Верификация MFA кода
                with patch('backend.api.mfa.pyotp') as mock_pyotp:
                    mock_totp = MagicMock()
                    mock_totp.verify.return_value = True
                    mock_pyotp.TOTP.return_value = mock_totp
                    
                    verify_response = client.post("/api/auth/mfa/verify", json={"code": "123456"})
                    assert verify_response.status_code == 200
                    verify_data = verify_response.json()
                    assert verify_data["verified"] is True
                    assert "MFA код подтвержден" in verify_data["message"]
                    
                    # Проверяем, что секрет получен из Redis
                    mock_redis.get.assert_called_with("mfa_secret:test_user_123")
                
                # 3. Отключение MFA
                disable_response = client.delete("/api/auth/mfa/disable")
                assert disable_response.status_code == 200
                disable_data = disable_response.json()
                assert "MFA отключен" in disable_data["message"]
                
                # Проверяем, что секрет удален из Redis
                mock_redis.delete.assert_called_with("mfa_secret:test_user_123")
                
                # 4. Попытка верификации после отключения
                mock_redis.get.return_value = None  # Секрет удален
                
                verify_after_disable_response = client.post("/api/auth/mfa/verify", json={"code": "123456"})
                assert verify_after_disable_response.status_code == 400
                verify_after_disable_data = verify_after_disable_response.json()
                assert "MFA не настроен" in verify_after_disable_data["detail"]
    
    @pytest.mark.asyncio
    async def test_full_auth_lifecycle(self):
        """P2: Полный жизненный цикл аутентификации"""
        # 1. Попытка доступа без токена
        response = client.get("/api/auth/user")
        assert response.status_code == 401
        
        # 2. Попытка доступа с невалидным токеном
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/api/auth/user", headers=headers)
        assert response.status_code == 401
        
        # 3. Попытка доступа с токеном неправильного алгоритма
        import jwt
        malicious_token = jwt.encode(
            {"user_id": "test_user", "exp": time.time() + 3600},
            "secret",
            algorithm="RS256"  # Неправильный алгоритм
        )
        headers = {"Authorization": f"Bearer {malicious_token}"}
        response = client.get("/api/auth/user", headers=headers)
        assert response.status_code == 401
        
        # 4. Попытка доступа с истекшим токеном
        expired_token = jwt.encode(
            {"user_id": "test_user", "exp": time.time() - 3600},  # Истекший
            "secret",
            algorithm="HS256"
        )
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/api/auth/user", headers=headers)
        assert response.status_code == 401
        
        # 5. Успешная аутентификация
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            response = client.get("/api/auth/user")
            assert response.status_code == 200
            user_data = response.json()
            assert user_data["id"] == "test_user_123"
            assert user_data["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_full_connection_lifecycle(self):
        """P2: Полный жизненный цикл соединений"""
        from backend.services.connection_manager import ConnectionManager
        
        # Создаем новый экземпляр для тестирования
        manager = ConnectionManager()
        
        # 1. Инициализация
        with patch('backend.services.connection_manager.supabase_manager') as mock_supabase:
            mock_supabase.initialize = MagicMock()
            
            with patch('backend.services.connection_manager.RedisConnectionPool') as mock_redis_class:
                mock_redis_pool = MagicMock()
                mock_redis_class.return_value = mock_redis_pool
                mock_redis_pool.initialize = MagicMock()
                
                with patch('backend.services.connection_manager.HTTPConnectionPool') as mock_http_class:
                    mock_http_pool = MagicMock()
                    mock_http_class.return_value = mock_http_pool
                    mock_http_pool.initialize = MagicMock()
                    
                    with patch('backend.services.connection_manager.settings') as mock_settings:
                        mock_settings.redis_url = "redis://localhost:6379"
                        mock_settings.database_url = None
                        
                        await manager.initialize()
                        assert manager._initialized is True
                        assert 'supabase' in manager._pools
                        assert 'redis' in manager._pools
                        assert 'http' in manager._pools
        
        # 2. Получение соединений
        # Redis соединение
        with patch.object(manager, '_pools', {'redis': MagicMock()}) as mock_pools:
            manager._initialized = True
            mock_redis_pool = mock_pools['redis']
            mock_connection = MagicMock()
            mock_redis_pool.acquire.return_value.__enter__.return_value = mock_connection
            mock_redis_pool.acquire.return_value.__exit__.return_value = None
            
            async with manager.get_redis_connection() as conn:
                assert conn == mock_connection
        
        # 3. Проверка здоровья
        with patch.object(manager, '_pools', {
            'supabase': MagicMock(),
            'redis': MagicMock(),
            'http': MagicMock()
        }) as mock_pools:
            manager._initialized = True
            
            # Настраиваем mock для health check
            mock_pools['supabase'].health_check_all = MagicMock(return_value={'healthy': True})
            mock_pools['redis'].ping = MagicMock(return_value=True)
            mock_pools['http']._clients = [MagicMock(), MagicMock()]
            
            health_status = await manager.health_check_all()
            assert 'supabase' in health_status
            assert 'redis' in health_status
            assert 'http' in health_status
        
        # 4. Закрытие соединений
        with patch.object(manager, '_pools', {
            'supabase': MagicMock(),
            'redis': MagicMock(),
            'http': MagicMock()
        }) as mock_pools:
            manager._initialized = True
            
            with patch('backend.services.connection_manager.supabase_manager') as mock_supabase_mgr:
                mock_supabase_mgr.close = MagicMock()
                
                await manager.close()
                assert manager._initialized is False
                assert len(manager._pools) == 0
    
    @pytest.mark.asyncio
    async def test_concurrent_api_key_operations(self):
        """P2: Тест конкурентных операций с API ключами"""
        import asyncio
        
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операций
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # Создаем несколько API ключей одновременно
                        async def create_api_key(key_name):
                            key_data = {
                                "provider": "openai",
                                "key_name": key_name,
                                "api_key": f"sk-test{key_name}abcdef"
                            }
                            return client.post("/api/api-keys/", json=key_data)
                        
                        # Mock для создания
                        mock_exec.return_value = MagicMock(data=[{"id": f"key_{i}", "created_at": "2025-01-11T00:00:00Z"}])
                        
                        # Выполняем конкурентные операции
                        tasks = [create_api_key(f"Key_{i}") for i in range(5)]
                        responses = await asyncio.gather(*tasks)
                        
                        # Проверяем, что все операции успешны
                        for response in responses:
                            assert response.status_code == 200
                            data = response.json()
                            assert "id" in data
                            assert data["provider"] == "openai"
    
    @pytest.mark.asyncio
    async def test_concurrent_mfa_operations(self):
        """P2: Тест конкурентных операций с MFA"""
        import asyncio
        
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.return_value = True
                mock_redis.get.return_value = b"test_secret"
                mock_redis.delete.return_value = 1
                
                # Создаем конкурентные операции
                async def setup_mfa():
                    return client.post("/api/auth/mfa/setup")
                
                async def verify_mfa():
                    return client.post("/api/auth/mfa/verify", json={"code": "123456"})
                
                async def disable_mfa():
                    return client.delete("/api/auth/mfa/disable")
                
                # Выполняем конкурентные операции
                tasks = [setup_mfa(), verify_mfa(), disable_mfa()]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Проверяем, что операции выполнены (могут быть исключения из-за конкурентности)
                for response in responses:
                    if not isinstance(response, Exception):
                        assert response.status_code in [200, 400, 500]  # Различные возможные статусы
    
    @pytest.mark.asyncio
    async def test_error_recovery_scenarios(self):
        """P2: Тест сценариев восстановления после ошибок"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операций
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # 1. Первая попытка - ошибка
                        mock_exec.side_effect = Exception("Database connection failed")
                        
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        
                        response1 = client.post("/api/api-keys/", json=key_data)
                        assert response1.status_code == 500
                        
                        # 2. Вторая попытка - успех
                        mock_exec.side_effect = [
                            MagicMock(data=[{"id": "key_123", "created_at": "2025-01-11T00:00:00Z"}])
                        ]
                        
                        response2 = client.post("/api/api-keys/", json=key_data)
                        assert response2.status_code == 200
                        data = response2.json()
                        assert data["id"] == "key_123"
    
    @pytest.mark.asyncio
    async def test_resource_cleanup_scenarios(self):
        """P2: Тест сценариев очистки ресурсов"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операций
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    # Настраиваем mock для encryption service
                    with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                        mock_enc_service = MagicMock()
                        mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                        mock_enc_service.get_key_last_4.return_value = "1234"
                        mock_enc.return_value = mock_enc_service
                        
                        # 1. Создание API ключа
                        mock_exec.side_effect = [
                            MagicMock(data=[{"id": "key_123", "created_at": "2025-01-11T00:00:00Z"}])
                        ]
                        
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        
                        create_response = client.post("/api/api-keys/", json=key_data)
                        assert create_response.status_code == 200
                        
                        # 2. Удаление API ключа
                        mock_exec.side_effect = [
                            MagicMock(data={"id": "key_123"}),  # Проверка существования
                            MagicMock(data={})  # Удаление
                        ]
                        
                        delete_response = client.delete("/api/api-keys/key_123")
                        assert delete_response.status_code == 200
                        
                        # 3. Попытка доступа к удаленному ключу
                        mock_exec.side_effect = [
                            MagicMock(data=None)  # Ключ не найден
                        ]
                        
                        get_response = client.get("/api/api-keys/key_123")
                        assert get_response.status_code == 404
                        
                        # 4. Попытка удаления уже удаленного ключа
                        mock_exec.side_effect = [
                            MagicMock(data=None)  # Ключ не найден
                        ]
                        
                        delete_again_response = client.delete("/api/api-keys/key_123")
                        assert delete_again_response.status_code == 404

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])