"""
Тесты граничных случаев безопасности API ключей
Найденные риски: неправильная обработка ключей, утечки в логах
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.encryption_service import get_encryption_service

client = TestClient(app)

class TestAPIKeySecurityBoundaries:
    """Тесты граничных случаев безопасности API ключей"""
    
    def test_api_key_not_logged_in_plain_text(self):
        """Тест: API ключи не логируются в открытом виде"""
        # Тестируем, что логирование не содержит реальных ключей
        with patch('backend.main.logger') as mock_logger:
            response = client.post("/api/ai/chat", json={
                "message": "test message",
                "api_key": "sk-1234567890abcdef"  # Настоящий ключ не должен попасть в логи
            })
            
            # Проверяем все вызовы логгера
            for call in mock_logger.method_calls:
                call_args = str(call)
                assert "sk-1234567890abcdef" not in call_args, "API ключ не должен быть в логах"
                assert "sk-" not in call_args or "mock" in call_args.lower(), "Реальные API ключи не должны быть в логах"
    
    def test_encrypted_api_key_decryption_failure_handling(self):
        """Тест: правильная обработка ошибок расшифровки API ключей"""
        encryption_service = get_encryption_service()
        
        # Тестируем с поврежденными данными
        corrupted_key = "corrupted_encrypted_data"
        
        with pytest.raises(Exception):
            encryption_service.decrypt_api_key(corrupted_key, "test_user_id")
    
    def test_api_key_validation_empty_string(self):
        """Тест: валидация пустых API ключей"""
        with patch('backend.services.ai_service.get_ai_service') as mock_ai:
            mock_ai.return_value.validate_all_keys.return_value = {"openai": False}
            
            response = client.post("/api/ai/validate-keys", json={
                "openai": ""  # Пустой ключ
            })
            
            assert response.status_code in [400, 422]
    
    def test_api_key_validation_invalid_format(self):
        """Тест: валидация неправильного формата API ключей"""
        with patch('backend.services.ai_service.get_ai_service') as mock_ai:
            mock_ai.return_value.validate_all_keys.return_value = {"openai": False}
            
            invalid_keys = [
                "invalid-key",           # Неправильный формат
                "sk-",                   # Слишком короткий
                "sk-" + "a" * 1000,     # Слишком длинный
                "sk-invalid_chars_!@#", # Недопустимые символы
            ]
            
            for invalid_key in invalid_keys:
                response = client.post("/api/ai/validate-keys", json={
                    "openai": invalid_key
                })
                assert response.status_code in [400, 422], f"Ключ '{invalid_key}' должен быть отклонен"
    
    def test_api_key_rate_limiting_per_provider(self):
        """Тест: rate limiting для разных провайдеров API"""
        # Симулируем превышение лимитов
        with patch('backend.services.ai_service.get_ai_service') as mock_ai:
            mock_ai.return_value.route_request.side_effect = Exception("Rate limit exceeded")
            
            response = client.post("/api/ai/chat", json={
                "message": "test message",
                "provider": "openai"
            })
            
            assert response.status_code in [429, 500]
    
    def test_api_key_encryption_consistency(self):
        """Тест: консистентность шифрования API ключей"""
        encryption_service = get_encryption_service()
        
        original_key = "sk-1234567890abcdef1234567890abcdef"
        user_id = "test_user_123"
        
        # Шифруем ключ дважды
        encrypted1 = encryption_service.encrypt_api_key(original_key, user_id)
        encrypted2 = encryption_service.encrypt_api_key(original_key, user_id)
        
        # Зашифрованные версии должны быть разными (из-за соли)
        assert encrypted1 != encrypted2
        
        # Но расшифровка должна давать одинаковый результат
        decrypted1 = encryption_service.decrypt_api_key(encrypted1, user_id)
        decrypted2 = encryption_service.decrypt_api_key(encrypted2, user_id)
        
        assert decrypted1 == original_key
        assert decrypted2 == original_key
        assert decrypted1 == decrypted2
    
    def test_api_key_access_control_user_isolation(self):
        """Тест: изоляция API ключей между пользователями"""
        encryption_service = get_encryption_service()
        
        original_key = "sk-1234567890abcdef1234567890abcdef"
        user1_id = "user_1"
        user2_id = "user_2"
        
        # Шифруем ключ для пользователя 1
        encrypted_key = encryption_service.encrypt_api_key(original_key, user1_id)
        
        # Пользователь 2 не должен иметь возможность расшифровать ключ пользователя 1
        with pytest.raises(Exception):
            encryption_service.decrypt_api_key(encrypted_key, user2_id)
    
    def test_api_key_storage_security_headers(self):
        """Тест: безопасность заголовков при работе с API ключами"""
        response = client.post("/api/api-keys", json={
            "provider_name": "openai",
            "api_key": "sk-test_key",
            "description": "Test key"
        })
        
        # Проверяем, что ключ не возвращается в ответе
        if response.status_code == 200:
            response_data = response.json()
            assert "api_key" not in str(response_data) or "encrypted" in str(response_data)
            assert "sk-test_key" not in str(response_data)
    
    def test_api_key_memory_cleanup(self):
        """Тест: очистка API ключей из памяти"""
        # Этот тест проверяет, что ключи не остаются в памяти после использования
        encryption_service = get_encryption_service()
        
        original_key = "sk-sensitive_key_that_should_be_cleaned"
        user_id = "test_user"
        
        # Шифруем и расшифровываем
        encrypted = encryption_service.encrypt_api_key(original_key, user_id)
        decrypted = encryption_service.decrypt_api_key(encrypted, user_id)
        
        assert decrypted == original_key
        
        # Проверяем, что после операций ключ не остается в атрибутах объекта
        service_attrs = [attr for attr in dir(encryption_service) if not attr.startswith('_')]
        for attr_name in service_attrs:
            attr_value = getattr(encryption_service, attr_name)
            if isinstance(attr_value, str):
                assert original_key not in attr_value, f"Ключ найден в атрибуте {attr_name}"
    
    @pytest.mark.asyncio
    async def test_concurrent_api_key_operations(self):
        """Тест: одновременные операции с API ключами"""
        encryption_service = get_encryption_service()
        
        async def encrypt_decrypt_cycle(key_suffix):
            original_key = f"sk-concurrent_test_key_{key_suffix}"
            user_id = f"user_{key_suffix}"
            
            encrypted = encryption_service.encrypt_api_key(original_key, user_id)
            decrypted = encryption_service.decrypt_api_key(encrypted, user_id)
            
            return decrypted == original_key
        
        # Запускаем множественные операции одновременно
        tasks = [encrypt_decrypt_cycle(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Все операции должны быть успешными
        assert all(results), "Все одновременные операции должны быть успешными"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])