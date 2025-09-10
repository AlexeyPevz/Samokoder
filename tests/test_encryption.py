"""
Unit тесты для сервиса шифрования API ключей
"""

import pytest
from backend.services.encryption import APIKeyEncryption

class TestAPIKeyEncryption:
    """Тесты для сервиса шифрования API ключей"""
    
    @pytest.fixture
    def encryption_service(self):
        """Фикстура для создания сервиса шифрования"""
        return APIKeyEncryption()
    
    def test_encrypt_decrypt_cycle(self, encryption_service):
        """Тест полного цикла шифрования-расшифровки"""
        original_key = "sk-1234567890abcdef1234567890abcdef"
        
        # Шифруем ключ
        encrypted_key = encryption_service.encrypt_api_key(original_key)
        
        # Проверяем, что зашифрованный ключ отличается от оригинального
        assert encrypted_key != original_key
        assert len(encrypted_key) > len(original_key)
        
        # Расшифровываем ключ
        decrypted_key = encryption_service.decrypt_api_key(encrypted_key)
        
        # Проверяем, что расшифрованный ключ совпадает с оригинальным
        assert decrypted_key == original_key
    
    def test_encrypt_different_keys(self, encryption_service):
        """Тест шифрования разных ключей"""
        key1 = "sk-1234567890abcdef1234567890abcdef"
        key2 = "sk-abcdef1234567890abcdef1234567890"
        
        encrypted1 = encryption_service.encrypt_api_key(key1)
        encrypted2 = encryption_service.encrypt_api_key(key2)
        
        # Зашифрованные ключи должны быть разными
        assert encrypted1 != encrypted2
        
        # Расшифровка должна работать корректно
        assert encryption_service.decrypt_api_key(encrypted1) == key1
        assert encryption_service.decrypt_api_key(encrypted2) == key2
    
    def test_encrypt_same_key_multiple_times(self, encryption_service):
        """Тест многократного шифрования одного ключа"""
        original_key = "sk-1234567890abcdef1234567890abcdef"
        
        encrypted1 = encryption_service.encrypt_api_key(original_key)
        encrypted2 = encryption_service.encrypt_api_key(original_key)
        
        # Зашифрованные версии должны быть разными (из-за случайной соли)
        assert encrypted1 != encrypted2
        
        # Но расшифровка должна давать одинаковый результат
        assert encryption_service.decrypt_api_key(encrypted1) == original_key
        assert encryption_service.decrypt_api_key(encrypted2) == original_key
    
    def test_decrypt_invalid_key(self, encryption_service):
        """Тест расшифровки невалидного ключа"""
        with pytest.raises(ValueError) as exc_info:
            encryption_service.decrypt_api_key("invalid-encrypted-key")
        assert "Ошибка расшифровки API ключа" in str(exc_info.value)
    
    def test_encrypt_empty_key(self, encryption_service):
        """Тест шифрования пустого ключа"""
        with pytest.raises(ValueError) as exc_info:
            encryption_service.encrypt_api_key("")
        assert "Ошибка шифрования API ключа" in str(exc_info.value)
    
    def test_get_last_4_chars(self, encryption_service):
        """Тест получения последних 4 символов"""
        key = "sk-1234567890abcdef1234567890abcdef"
        last_4 = encryption_service.get_last_4_chars(key)
        assert last_4 == "...cdef"
        
        # Тест с коротким ключом
        short_key = "abc"
        last_4_short = encryption_service.get_last_4_chars(short_key)
        assert last_4_short == "..."
    
    def test_mask_api_key(self, encryption_service):
        """Тест маскирования API ключа"""
        key = "sk-1234567890abcdef1234567890abcdef"
        masked = encryption_service.mask_api_key(key)
        
        # Проверяем, что ключ замаскирован
        assert masked.startswith("*")
        assert masked.endswith("cdef")
        assert len(masked) == len(key)
        
        # Тест с кастомным количеством видимых символов
        masked_2 = encryption_service.mask_api_key(key, visible_chars=2)
        assert masked_2.endswith("ef")
        assert len(masked_2) == len(key)
    
    def test_mask_short_key(self, encryption_service):
        """Тест маскирования короткого ключа"""
        short_key = "abc"
        masked = encryption_service.mask_api_key(short_key)
        assert masked == "***"
    
    def test_validate_api_key_format_openai(self, encryption_service):
        """Тест валидации формата OpenAI ключа"""
        # Валидный OpenAI ключ
        valid_key = "sk-1234567890abcdef1234567890abcdef"
        assert encryption_service.validate_api_key_format(valid_key, "openai") is True
        
        # Невалидный OpenAI ключ (не начинается с sk-)
        invalid_key = "pk-1234567890abcdef1234567890abcdef"
        assert encryption_service.validate_api_key_format(invalid_key, "openai") is False
        
        # Слишком короткий ключ
        short_key = "sk-short"
        assert encryption_service.validate_api_key_format(short_key, "openai") is False
    
    def test_validate_api_key_format_anthropic(self, encryption_service):
        """Тест валидации формата Anthropic ключа"""
        # Валидный Anthropic ключ
        valid_key = "sk-ant-1234567890abcdef1234567890abcdef"
        assert encryption_service.validate_api_key_format(valid_key, "anthropic") is True
        
        # Невалидный Anthropic ключ
        invalid_key = "sk-1234567890abcdef1234567890abcdef"
        assert encryption_service.validate_api_key_format(invalid_key, "anthropic") is False
    
    def test_validate_api_key_format_openrouter(self, encryption_service):
        """Тест валидации формата OpenRouter ключа"""
        # Валидный OpenRouter ключ
        valid_key = "sk-or-1234567890abcdef1234567890abcdef"
        assert encryption_service.validate_api_key_format(valid_key, "openrouter") is True
        
        # Невалидный OpenRouter ключ
        invalid_key = "sk-1234567890abcdef1234567890abcdef"
        assert encryption_service.validate_api_key_format(invalid_key, "openrouter") is False
    
    def test_validate_api_key_format_groq(self, encryption_service):
        """Тест валидации формата Groq ключа"""
        # Валидный Groq ключ (длинный)
        valid_key = "gsk_1234567890abcdef1234567890abcdef"
        assert encryption_service.validate_api_key_format(valid_key, "groq") is True
        
        # Слишком короткий ключ
        short_key = "gsk_short"
        assert encryption_service.validate_api_key_format(short_key, "groq") is False
    
    def test_validate_api_key_format_unknown_provider(self, encryption_service):
        """Тест валидации для неизвестного провайдера"""
        # Должна проходить базовая проверка
        valid_key = "1234567890abcdef"
        assert encryption_service.validate_api_key_format(valid_key, "unknown") is True
        
        # Слишком короткий ключ
        short_key = "short"
        assert encryption_service.validate_api_key_format(short_key, "unknown") is False
    
    def test_validate_empty_key(self, encryption_service):
        """Тест валидации пустого ключа"""
        assert encryption_service.validate_api_key_format("", "openai") is False
        assert encryption_service.validate_api_key_format(None, "openai") is False
    
    def test_validate_whitespace_key(self, encryption_service):
        """Тест валидации ключа из пробелов"""
        assert encryption_service.validate_api_key_format("   ", "openai") is False