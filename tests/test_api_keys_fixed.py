"""
Исправленные тесты для API Keys с правильными фикстурами
"""

import pytest
from unittest.mock import patch, MagicMock

class TestAPIKeysFixed:
    """Исправленные тесты для API Keys"""
    
    def test_get_api_keys_success(self, client, mock_connection_manager, mock_supabase_operation, mock_current_user):
        """Тест успешного получения списка API ключей"""
        # Настраиваем mock для Supabase операции
        mock_supabase_operation.return_value = MagicMock(data=[
            {
                "id": "key_123",
                "provider_name": "openai",
                "key_name": "Test Key 1",
                "api_key_last_4": "1234",
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
        assert data["total_count"] == 1
        assert len(data["keys"]) == 1
        
        # Проверяем структуру ключа
        first_key = data["keys"][0]
        assert first_key["id"] == "key_123"
        assert first_key["provider"] == "openai"
        assert first_key["key_name"] == "Test Key 1"
        assert first_key["key_last_4"] == "1234"
        assert first_key["is_active"] is True
    
    def test_get_api_keys_empty(self, client, mock_connection_manager, mock_supabase_operation, mock_current_user):
        """Тест получения пустого списка API ключей"""
        # Настраиваем mock для пустого результата
        mock_supabase_operation.return_value = MagicMock(data=[])
        
        # Выполняем получение API ключей
        response = client.get("/api/api-keys/")
        
        # Критерии успеха
        assert response.status_code == 200
        data = response.json()
        assert "keys" in data
        assert "total_count" in data
        assert data["total_count"] == 0
        assert len(data["keys"]) == 0
    
    def test_get_api_key_success(self, client, mock_connection_manager, mock_supabase_operation, mock_current_user):
        """Тест успешного получения конкретного API ключа"""
        # Настраиваем mock для Supabase операции
        mock_supabase_operation.return_value = MagicMock(data={
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
    
    def test_get_api_key_not_found(self, client, mock_connection_manager, mock_supabase_operation, mock_current_user):
        """Тест получения несуществующего API ключа"""
        # Настраиваем mock для ключа не найден
        mock_supabase_operation.return_value = MagicMock(data=None)
        
        # Выполняем получение несуществующего API ключа
        response = client.get("/api/api-keys/nonexistent_key")
        
        # Критерии успеха - должен вернуть 404
        assert response.status_code == 404
        assert "API ключ не найден" in response.json()["detail"]
    
    def test_create_api_key_success(self, client, mock_connection_manager, mock_supabase_operation, mock_encryption_service, mock_current_user):
        """Тест успешного создания API ключа"""
        # Настраиваем mock для создания
        mock_supabase_operation.return_value = MagicMock(data=[{
            "id": "key_123",
            "created_at": "2025-01-11T00:00:00Z"
        }])
        
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
        # ID генерируется автоматически, проверяем что он есть
        assert "id" in data
        assert data["provider"] == "openai"
        assert data["key_name"] == "Test Key"
        assert data["key_last_4"] == "1234"
        assert data["is_active"] is True
    
    def test_toggle_api_key_success(self, client, mock_connection_manager, mock_supabase_operation, mock_current_user):
        """Тест успешного переключения статуса API ключа"""
        # Настраиваем mock для Supabase операций
        mock_supabase_operation.side_effect = [
            MagicMock(data={"is_active": True}),  # Получение текущего статуса
            MagicMock(data={})  # Обновление статуса
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
    
    def test_delete_api_key_success(self, client, mock_connection_manager, mock_supabase_operation, mock_current_user):
        """Тест успешного удаления API ключа"""
        # Настраиваем mock для Supabase операций
        mock_supabase_operation.side_effect = [
            MagicMock(data={"id": "key_123"}),  # Проверка существования
            MagicMock(data={})  # Удаление
        ]
        
        # Выполняем удаление API ключа
        response = client.delete("/api/api-keys/key_123")
        
        # Критерии успеха
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "API ключ удален" in data["message"]
    
    def test_delete_api_key_not_found(self, client, mock_connection_manager, mock_supabase_operation, mock_current_user):
        """Тест удаления несуществующего API ключа"""
        # Настраиваем mock для ключа не найден
        mock_supabase_operation.return_value = MagicMock(data=None)
        
        # Выполняем удаление несуществующего API ключа
        response = client.delete("/api/api-keys/nonexistent_key")
        
        # Критерии успеха - должен вернуть 404
        assert response.status_code == 404
        assert "API ключ не найден" in response.json()["detail"]

if __name__ == "__main__":
    pytest.main([__file__, "-v"])