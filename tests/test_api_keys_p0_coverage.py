"""
P0 тесты для API Keys - критические пробелы в покрытии
Блокируют мёрж до зелёного прогона
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

class TestAPIKeysP0Coverage:
    """P0 тесты для критических пробелов в API Keys"""
    
    # === P0 - КРИТИЧЕСКИЕ ТЕСТЫ (БЛОКИРУЮТ МЁРЖ) ===
    
    @pytest.mark.asyncio
    async def test_get_api_keys_success(self):
        """P0: Тест успешного получения списка API ключей"""
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
                            "provider_name": "openai",
                            "key_name": "Test Key 1",
                            "api_key_last_4": "1234",
                            "is_active": True,
                            "created_at": "2025-01-11T00:00:00Z"
                        },
                        {
                            "id": "key_456",
                            "provider_name": "anthropic",
                            "key_name": "Test Key 2",
                            "api_key_last_4": "5678",
                            "is_active": False,
                            "created_at": "2025-01-11T01:00:00Z"
                        }
                    ])
                    
                    # Выполняем получение API ключей
                    response = client.get("/api/api-keys/")
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert "keys" in data
                    assert "total_count" in data
                    assert data["total_count"] == 2
                    assert len(data["keys"]) == 2
                    
                    # Проверяем структуру первого ключа
                    first_key = data["keys"][0]
                    assert first_key["id"] == "key_123"
                    assert first_key["provider"] == "openai"
                    assert first_key["key_name"] == "Test Key 1"
                    assert first_key["key_last_4"] == "1234"
                    assert first_key["is_active"] is True
                    assert first_key["created_at"] == "2025-01-11T00:00:00Z"
                    
                    # Проверяем использование connection manager
                    mock_conn_mgr.get_pool.assert_called_with('supabase')
    
    @pytest.mark.asyncio
    async def test_get_api_keys_empty(self):
        """P0: Тест получения пустого списка API ключей"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции (пустой результат)
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=[])
                    
                    # Выполняем получение API ключей
                    response = client.get("/api/api-keys/")
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert "keys" in data
                    assert "total_count" in data
                    assert data["total_count"] == 0
                    assert len(data["keys"]) == 0
    
    @pytest.mark.asyncio
    async def test_get_api_keys_connection_manager_unavailable(self):
        """P0: Тест получения API ключей при недоступности connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.return_value = None
                
                # Выполняем получение API ключей
                response = client.get("/api/api-keys/")
                
                # Критерии успеха - должен вернуть пустой список
                assert response.status_code == 200
                data = response.json()
                assert "keys" in data
                assert "total_count" in data
                assert data["total_count"] == 0
                assert len(data["keys"]) == 0
    
    @pytest.mark.asyncio
    async def test_get_api_keys_database_error(self):
        """P0: Тест получения API ключей при ошибке базы данных"""
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
                    
                    # Выполняем получение API ключей
                    response = client.get("/api/api-keys/")
                    
                    # Критерии успеха - должен вернуть 500
                    assert response.status_code == 500
                    assert "Ошибка получения API ключей" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_api_key_success(self):
        """P0: Тест успешного получения конкретного API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data={
                        "id": "key_123",
                        "provider_name": "openai",
                        "key_name": "Test Key",
                        "api_key_last_4": "1234",
                        "is_active": True,
                        "created_at": "2025-01-11T00:00:00Z"
                    })
                    
                    # Выполняем получение конкретного API ключа
                    response = client.get("/api/api-keys/key_123")
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert data["id"] == "key_123"
                    assert data["provider"] == "openai"
                    assert data["key_name"] == "Test Key"
                    assert data["key_last_4"] == "1234"
                    assert data["is_active"] is True
                    assert data["created_at"] == "2025-01-11T00:00:00Z"
                    
                    # Проверяем использование connection manager
                    mock_conn_mgr.get_pool.assert_called_with('supabase')
    
    @pytest.mark.asyncio
    async def test_get_api_key_not_found(self):
        """P0: Тест получения несуществующего API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции (ключ не найден)
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=None)
                    
                    # Выполняем получение несуществующего API ключа
                    response = client.get("/api/api-keys/nonexistent_key")
                    
                    # Критерии успеха - должен вернуть 404
                    assert response.status_code == 404
                    assert "API ключ не найден" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_api_key_connection_manager_unavailable(self):
        """P0: Тест получения API ключа при недоступности connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.return_value = None
                
                # Выполняем получение API ключа
                response = client.get("/api/api-keys/key_123")
                
                # Критерии успеха - должен вернуть 503
                assert response.status_code == 503
                assert "Supabase недоступен" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_success(self):
        """P0: Тест успешного переключения статуса API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операций
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    # Первый вызов - получение текущего статуса
                    # Второй вызов - обновление статуса
                    mock_exec.side_effect = [
                        MagicMock(data={"is_active": True}),  # Текущий статус
                        MagicMock(data={})  # Результат обновления
                    ]
                    
                    # Выполняем переключение статуса API ключа
                    response = client.put("/api/api-keys/key_123/toggle")
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert "is_active" in data
                    assert data["is_active"] is False  # Переключили с True на False
                    assert "выключен" in data["message"]
                    
                    # Проверяем использование connection manager
                    mock_conn_mgr.get_pool.assert_called_with('supabase')
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_not_found(self):
        """P0: Тест переключения несуществующего API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции (ключ не найден)
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=None)
                    
                    # Выполняем переключение несуществующего API ключа
                    response = client.put("/api/api-keys/nonexistent_key/toggle")
                    
                    # Критерии успеха - должен вернуть 404
                    assert response.status_code == 404
                    assert "API ключ не найден" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_connection_manager_unavailable(self):
        """P0: Тест переключения API ключа при недоступности connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.return_value = None
                
                # Выполняем переключение API ключа
                response = client.put("/api/api-keys/key_123/toggle")
                
                # Критерии успеха - должен вернуть 503
                assert response.status_code == 503
                assert "Supabase недоступен" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_delete_api_key_success(self):
        """P0: Тест успешного удаления API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операций
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    # Первый вызов - проверка существования ключа
                    # Второй вызов - удаление ключа
                    mock_exec.side_effect = [
                        MagicMock(data={"id": "key_123"}),  # Ключ найден
                        MagicMock(data={})  # Результат удаления
                    ]
                    
                    # Выполняем удаление API ключа
                    response = client.delete("/api/api-keys/key_123")
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert "message" in data
                    assert "API ключ удален" in data["message"]
                    
                    # Проверяем использование connection manager
                    mock_conn_mgr.get_pool.assert_called_with('supabase')
    
    @pytest.mark.asyncio
    async def test_delete_api_key_not_found(self):
        """P0: Тест удаления несуществующего API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_supabase = MagicMock()
                mock_conn_mgr.get_pool.return_value = mock_supabase
                
                # Настраиваем mock для Supabase операции (ключ не найден)
                with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=None)
                    
                    # Выполняем удаление несуществующего API ключа
                    response = client.delete("/api/api-keys/nonexistent_key")
                    
                    # Критерии успеха - должен вернуть 404
                    assert response.status_code == 404
                    assert "API ключ не найден" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_delete_api_key_connection_manager_unavailable(self):
        """P0: Тест удаления API ключа при недоступности connection manager"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для недоступности connection manager
            with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
                mock_conn_mgr.get_pool.return_value = None
                
                # Выполняем удаление API ключа
                response = client.delete("/api/api-keys/key_123")
                
                # Критерии успеха - должен вернуть 503
                assert response.status_code == 503
                assert "Supabase недоступен" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_delete_api_key_database_error(self):
        """P0: Тест удаления API ключа при ошибке базы данных"""
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
                    
                    # Выполняем удаление API ключа
                    response = client.delete("/api/api-keys/key_123")
                    
                    # Критерии успеха - должен вернуть 500
                    assert response.status_code == 500
                    assert "Ошибка удаления API ключа" in response.json()["detail"]

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])