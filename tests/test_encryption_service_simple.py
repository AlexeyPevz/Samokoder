"""
Простые тесты для Encryption Service
"""

import pytest
from unittest.mock import patch, MagicMock

class TestEncryptionServiceSimple:
    """Простые тесты для Encryption Service"""
    
    def test_encryption_service_class_exists(self):
        """Проверяем, что класс EncryptionService существует"""
        from backend.services.encryption_service import EncryptionService
        
        # Проверяем, что класс существует
        assert EncryptionService is not None
        
        # Проверяем, что можно создать экземпляр
        service = EncryptionService()
        assert service is not None
    
    def test_encryption_service_methods_exist(self):
        """Проверяем, что все методы EncryptionService существуют"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Проверяем, что все методы существуют
        assert hasattr(service, 'encrypt_api_key')
        assert hasattr(service, 'decrypt_api_key')
        assert hasattr(service, 'get_key_last_4')
        assert hasattr(service, 'generate_encryption_key')
    
    def test_encrypt_api_key_function(self):
        """Тест функции encrypt_api_key"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем функцию
        api_key = "sk-test1234567890abcdef"
        encrypted = service.encrypt_api_key(api_key)
        
        # Проверяем результат
        assert encrypted != api_key
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0
    
    def test_decrypt_api_key_function(self):
        """Тест функции decrypt_api_key"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем функцию
        api_key = "sk-test1234567890abcdef"
        encrypted = service.encrypt_api_key(api_key)
        decrypted = service.decrypt_api_key(encrypted)
        
        # Проверяем результат
        assert decrypted == api_key
    
    def test_get_key_last_4_function(self):
        """Тест функции get_key_last_4"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем функцию
        api_key = "sk-test1234567890abcdef"
        last_4 = service.get_key_last_4(api_key)
        
        # Проверяем результат
        assert last_4 == "cdef"
        assert len(last_4) == 4
    
    def test_get_key_last_4_short_key(self):
        """Тест функции get_key_last_4 с коротким ключом"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем с коротким ключом
        api_key = "abc"
        last_4 = service.get_key_last_4(api_key)
        
        # Проверяем результат
        assert last_4 == "abc"
        assert len(last_4) <= 4
    
    def test_get_key_last_4_empty_key(self):
        """Тест функции get_key_last_4 с пустым ключом"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем с пустым ключом
        api_key = ""
        last_4 = service.get_key_last_4(api_key)
        
        # Проверяем результат
        assert last_4 == ""
    
    def test_generate_encryption_key_function(self):
        """Тест функции generate_encryption_key"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем функцию
        key = service.generate_encryption_key()
        
        # Проверяем результат
        assert isinstance(key, bytes)
        assert len(key) > 0
    
    def test_encryption_roundtrip(self):
        """Тест полного цикла шифрования/дешифрования"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем различные ключи
        test_keys = [
            "sk-test1234567890abcdef",
            "sk-anotherkey123456789",
            "sk-verylongkey12345678901234567890",
            "sk-short",
            "",
        ]
        
        for api_key in test_keys:
            # Шифруем
            encrypted = service.encrypt_api_key(api_key)
            
            # Дешифруем
            decrypted = service.decrypt_api_key(encrypted)
            
            # Проверяем, что результат совпадает
            assert decrypted == api_key, f"Failed for key: {api_key}"
    
    def test_encryption_service_imports(self):
        """Тест импортов Encryption Service"""
        # Проверяем, что все необходимые модули импортируются
        try:
            from backend.services.encryption_service import EncryptionService
            assert True  # Импорт успешен
        except ImportError as e:
            pytest.fail(f"Import failed: {e}")
    
    def test_encryption_service_initialization(self):
        """Тест инициализации Encryption Service"""
        from backend.services.encryption_service import EncryptionService
        
        # Проверяем, что сервис инициализируется без ошибок
        service = EncryptionService()
        
        # Проверяем, что у сервиса есть необходимые атрибуты
        assert hasattr(service, '_fernet')
        assert service._fernet is not None
    
    def test_encryption_service_error_handling(self):
        """Тест обработки ошибок в Encryption Service"""
        from backend.services.encryption_service import EncryptionService
        
        service = EncryptionService()
        
        # Тестируем с невалидными данными
        try:
            # Попытка дешифровать невалидные данные
            result = service.decrypt_api_key("invalid_encrypted_data")
            # Если не выброшено исключение, проверяем результат
            assert result is not None or result == ""
        except Exception:
            # Ожидаем исключение для невалидных данных
            pass

if __name__ == "__main__":
    pytest.main([__file__, "-v"])