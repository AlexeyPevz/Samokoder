"""
ASVS V5: Тесты безопасности валидации и кодирования - рефакторированная версия
Разделены на специализированные классы для лучшей организации
"""

import pytest
import json
import base64
from security_patches.asvs_v5_validation_p0_fixes import ValidationSecurity

class BaseValidationTest:
    """Базовый класс для тестов валидации"""
    
    @pytest.fixture
    def validation_security(self):
        """Создать экземпляр ValidationSecurity"""
        return ValidationSecurity()

class TestInputValidation(BaseValidationTest):
    """Тесты валидации ввода"""
    
    def test_input_length_validation(self, validation_security):
        """V5.1.1: Тест валидации длины ввода"""
        # Нормальная длина
        assert validation_security.validate_input_length("normal input") is True
        
        # Пустой ввод
        assert validation_security.validate_input_length("") is True
        assert validation_security.validate_input_length(None) is True
        
        # Слишком длинный ввод
        long_input = "a" * 15000
        assert validation_security.validate_input_length(long_input) is False
        
        # Кастомный лимит
        assert validation_security.validate_input_length("test", max_length=10) is True
        assert validation_security.validate_input_length("test", max_length=3) is False

    def test_input_sanitization(self, validation_security):
        """V5.1.2: Тест санитизации ввода"""
        # HTML теги
        html_input = "<script>alert('xss')</script>"
        sanitized = validation_security.sanitize_input(html_input)
        assert "<script>" not in sanitized
        assert "alert" not in sanitized
        
        # SQL инъекции
        sql_input = "'; DROP TABLE users; --"
        sanitized = validation_security.sanitize_input(sql_input)
        assert "DROP TABLE" not in sanitized
        
        # Нормальный ввод
        normal_input = "Hello World"
        sanitized = validation_security.sanitize_input(normal_input)
        assert sanitized == normal_input

class TestDataEncoding(BaseValidationTest):
    """Тесты кодирования данных"""
    
    def test_base64_encoding(self, validation_security):
        """V5.1.3: Тест Base64 кодирования"""
        test_data = "Hello World"
        
        # Кодирование
        encoded = validation_security.encode_base64(test_data)
        assert encoded is not None
        assert isinstance(encoded, str)
        
        # Декодирование
        decoded = validation_security.decode_base64(encoded)
        assert decoded == test_data

    def test_json_encoding(self, validation_security):
        """V5.1.3: Тест JSON кодирования"""
        test_data = {"key": "value", "number": 123}
        
        # Кодирование
        encoded = validation_security.encode_json(test_data)
        assert encoded is not None
        assert isinstance(encoded, str)
        
        # Декодирование
        decoded = validation_security.decode_json(encoded)
        assert decoded == test_data

class TestValidationSecurity(BaseValidationTest):
    """Основные тесты безопасности валидации"""
    
    def test_validation_security_initialization(self, validation_security):
        """V5.1.4: Тест инициализации безопасности валидации"""
        assert hasattr(validation_security, 'max_input_length')
        assert hasattr(validation_security, 'allowed_chars')
        assert validation_security.max_input_length > 0
        assert isinstance(validation_security.allowed_chars, str)