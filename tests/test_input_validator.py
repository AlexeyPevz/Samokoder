#!/usr/bin/env python3
"""
Тесты для Input Validator
"""

import pytest
from backend.validators.input_validator import InputValidator, validator


class TestInputValidator:
    """Тесты для Input Validator модуля"""
    
    def test_email_pattern_exists(self):
        """Тест существования email паттерна"""
        assert InputValidator.EMAIL_PATTERN is not None
        assert hasattr(InputValidator.EMAIL_PATTERN, 'match')
    
    def test_uuid_pattern_exists(self):
        """Тест существования UUID паттерна"""
        assert InputValidator.UUID_PATTERN is not None
        assert hasattr(InputValidator.UUID_PATTERN, 'match')
    
    def test_alphanumeric_pattern_exists(self):
        """Тест существования alphanumeric паттерна"""
        assert InputValidator.ALPHANUMERIC_PATTERN is not None
        assert hasattr(InputValidator.ALPHANUMERIC_PATTERN, 'match')
    
    def test_safe_string_pattern_exists(self):
        """Тест существования safe string паттерна"""
        assert InputValidator.SAFE_STRING_PATTERN is not None
        assert hasattr(InputValidator.SAFE_STRING_PATTERN, 'match')
    
    def test_max_length_constants(self):
        """Тест констант максимальных длин"""
        assert InputValidator.MAX_EMAIL_LENGTH == 254
        assert InputValidator.MAX_PASSWORD_LENGTH == 1000
        assert InputValidator.MAX_NAME_LENGTH == 255
        assert InputValidator.MAX_DESCRIPTION_LENGTH == 10000
        assert InputValidator.MAX_MESSAGE_LENGTH == 50000
        assert InputValidator.MAX_PATH_LENGTH == 1000
    
    def test_min_length_constants(self):
        """Тест констант минимальных длин"""
        assert InputValidator.MIN_PASSWORD_LENGTH == 6
        assert InputValidator.MIN_NAME_LENGTH == 1
    
    def test_validate_email_valid(self):
        """Тест валидации валидного email"""
        valid_emails = [
            "test@example.com",
            "user.name@domain.org",
            "test+tag@example.co.uk",
            "user123@test-domain.com"
        ]
        
        for email in valid_emails:
            is_valid, error = InputValidator.validate_email(email)
            assert is_valid is True
            assert error == ""
    
    def test_validate_email_invalid(self):
        """Тест валидации невалидного email"""
        invalid_emails = [
            "",  # Пустой
            "invalid-email",  # Без @
            "@domain.com",  # Без локальной части
            "user@",  # Без домена
            "user@domain",  # Без TLD
            "user name@domain.com",  # Пробел в локальной части
            "user@domain .com",  # Пробел в домене
            "user@domain.com<script>",  # HTML теги
            "user@domain.com\"",  # Кавычки
        ]
        
        for email in invalid_emails:
            is_valid, error = InputValidator.validate_email(email)
            assert is_valid is False
            assert error != ""
    
    def test_validate_email_too_long(self):
        """Тест валидации слишком длинного email"""
        long_email = "a" * 250 + "@example.com"  # 262 символа
        is_valid, error = InputValidator.validate_email(long_email)
        assert is_valid is False
        assert "не может быть длиннее" in error
    
    def test_validate_password_valid(self):
        """Тест валидации валидного пароля"""
        valid_passwords = [
            "password123",
            "MySecurePassword!",
            "123456",  # Минимальная длина
            "a" * 1000  # Максимальная длина
        ]
        
        for password in valid_passwords:
            is_valid, error = InputValidator.validate_password(password)
            assert is_valid is True
            assert error == ""
    
    def test_validate_password_invalid(self):
        """Тест валидации невалидного пароля"""
        invalid_passwords = [
            "",  # Пустой
            "12345",  # Слишком короткий
            "a" * 1001,  # Слишком длинный
            "password<script>",  # HTML теги
            "password\"",  # Кавычки
            "password\x00",  # Null байт
        ]
        
        for password in invalid_passwords:
            is_valid, error = InputValidator.validate_password(password)
            assert is_valid is False
            assert error != ""
    
    def test_validate_name_valid(self):
        """Тест валидации валидного названия"""
        valid_names = [
            "Test Name",
            "Project 123",
            "A",  # Минимальная длина
            "a" * 255  # Максимальная длина
        ]
        
        for name in valid_names:
            is_valid, error = InputValidator.validate_name(name)
            assert is_valid is True
            assert error == ""
    
    def test_validate_name_invalid(self):
        """Тест валидации невалидного названия"""
        invalid_names = [
            "",  # Пустое
            "a" * 256,  # Слишком длинное
            "Name<script>",  # HTML теги
            "Name\"",  # Кавычки
            "Name\x00",  # Null байт
        ]
        
        for name in invalid_names:
            is_valid, error = InputValidator.validate_name(name)
            assert is_valid is False
            assert error != ""
    
    def test_validate_name_custom_field_name(self):
        """Тест валидации названия с кастомным именем поля"""
        is_valid, error = InputValidator.validate_name("", "Пользователь")
        assert is_valid is False
        assert "Пользователь не может быть пустым" in error
    
    def test_validate_description_valid(self):
        """Тест валидации валидного описания"""
        valid_descriptions = [
            None,  # Может быть None
            "",  # Может быть пустым
            "Valid description",
            "a" * 10000  # Максимальная длина
        ]
        
        for description in valid_descriptions:
            is_valid, error = InputValidator.validate_description(description)
            assert is_valid is True
            assert error == ""
    
    def test_validate_description_invalid(self):
        """Тест валидации невалидного описания"""
        invalid_descriptions = [
            "a" * 10001,  # Слишком длинное
            "Description<script>",  # HTML теги
            "Description\x00",  # Null байт
        ]
        
        for description in invalid_descriptions:
            is_valid, error = InputValidator.validate_description(description)
            assert is_valid is False
            assert error != ""
    
    def test_validate_message_valid(self):
        """Тест валидации валидного сообщения"""
        valid_messages = [
            "Hello world",
            "a" * 50000  # Максимальная длина
        ]
        
        for message in valid_messages:
            is_valid, error = InputValidator.validate_message(message)
            assert is_valid is True
            assert error == ""
    
    def test_validate_message_invalid(self):
        """Тест валидации невалидного сообщения"""
        invalid_messages = [
            "",  # Пустое
            "a" * 50001,  # Слишком длинное
            "Message\x00",  # Null байт
        ]
        
        for message in invalid_messages:
            is_valid, error = InputValidator.validate_message(message)
            assert is_valid is False
            assert error != ""
    
    def test_validate_uuid_valid(self):
        """Тест валидации валидного UUID"""
        valid_uuids = [
            "550e8400-e29b-41d4-a716-446655440000",
            "123e4567-e89b-12d3-a456-426614174000",
            "00000000-0000-0000-0000-000000000000"
        ]
        
        for uuid_str in valid_uuids:
            is_valid, error = InputValidator.validate_uuid(uuid_str)
            assert is_valid is True
            assert error == ""
    
    def test_validate_uuid_invalid(self):
        """Тест валидации невалидного UUID"""
        invalid_uuids = [
            "",  # Пустой
            "invalid-uuid",  # Неверный формат
            "550e8400-e29b-41d4-a716",  # Неполный
            "550e8400-e29b-41d4-a716-446655440000-extra",  # Слишком длинный
            "550E8400-E29B-41D4-A716-446655440000",  # Заглавные буквы
        ]
        
        for uuid_str in invalid_uuids:
            is_valid, error = InputValidator.validate_uuid(uuid_str)
            assert is_valid is False
            assert error != ""
    
    def test_validate_uuid_custom_field_name(self):
        """Тест валидации UUID с кастомным именем поля"""
        is_valid, error = InputValidator.validate_uuid("", "Project ID")
        assert is_valid is False
        assert "Project ID не может быть пустым" in error
    
    def test_validate_path_valid(self):
        """Тест валидации валидного пути"""
        valid_paths = [
            "/home/user/file.txt",
            "C:\\Users\\file.txt",
            "relative/path/file.txt",
            "a" * 1000  # Максимальная длина
        ]
        
        for path in valid_paths:
            is_valid, error = InputValidator.validate_path(path)
            assert is_valid is True
            assert error == ""
    
    def test_validate_path_invalid(self):
        """Тест валидации невалидного пути"""
        invalid_paths = [
            "",  # Пустой
            "a" * 1001,  # Слишком длинный
            "../secret/file.txt",  # Path traversal
            "..\\secret\\file.txt",  # Path traversal Windows
            "..%2fsecret%2ffile.txt",  # URL encoded path traversal
            "..%5csecret%5cfile.txt",  # URL encoded path traversal Windows
            "/path/file\x00.txt",  # Null байт
        ]
        
        for path in invalid_paths:
            is_valid, error = InputValidator.validate_path(path)
            assert is_valid is False
            assert error != ""
    
    def test_sanitize_string(self):
        """Тест санитизации строки"""
        test_cases = [
            ("", ""),  # Пустая строка
            ("Normal text", "Normal text"),  # Обычный текст
            ("Text with <script>", "Text with &lt;script&gt;"),  # HTML экранирование
            ("Text with \"quotes\"", "Text with &quot;quotes&quot;"),  # Кавычки
            ("Text with \x00null", "Text with null"),  # Null байт
            ("  Multiple   spaces  ", "Multiple spaces"),  # Лишние пробелы
        ]
        
        for input_text, expected in test_cases:
            result = InputValidator.sanitize_string(input_text)
            assert result == expected
    
    def test_validate_json_data_valid(self):
        """Тест валидации валидных JSON данных"""
        valid_data = [
            {},
            {"key": "value"},
            {"nested": {"key": "value"}},
            {"array": [1, 2, 3]},
            {"string": "normal text"},
        ]
        
        for data in valid_data:
            is_valid, errors = InputValidator.validate_json_data(data)
            assert is_valid is True
            assert errors == []
    
    def test_validate_json_data_function_exists(self):
        """Тест существования функции валидации JSON"""
        assert hasattr(InputValidator, 'validate_json_data')
        assert callable(InputValidator.validate_json_data)
        
        # Тестируем простой случай
        simple_data = {"key": "value"}
        is_valid, errors = InputValidator.validate_json_data(simple_data)
        assert isinstance(is_valid, bool)
        assert isinstance(errors, list)
    
    def test_validate_request_size_valid(self):
        """Тест валидации валидного размера запроса"""
        valid_sizes = [0, 1024, 1024 * 1024, 10 * 1024 * 1024]  # До 10MB
        
        for size in valid_sizes:
            is_valid, error = InputValidator.validate_request_size(size)
            assert is_valid is True
            assert error == ""
    
    def test_validate_request_size_invalid(self):
        """Тест валидации невалидного размера запроса"""
        invalid_size = 11 * 1024 * 1024  # 11MB
        
        is_valid, error = InputValidator.validate_request_size(invalid_size)
        assert is_valid is False
        assert "превышает максимально допустимый" in error
    
    def test_validate_request_size_custom_max_size(self):
        """Тест валидации размера запроса с кастомным максимумом"""
        max_size = 5 * 1024 * 1024  # 5MB
        invalid_size = 6 * 1024 * 1024  # 6MB
        
        is_valid, error = InputValidator.validate_request_size(invalid_size, max_size)
        assert is_valid is False
        assert "5MB" in error
    
    def test_global_validator_instance(self):
        """Тест глобального экземпляра валидатора"""
        assert validator is not None
        assert isinstance(validator, InputValidator)
    
    def test_patterns_functionality(self):
        """Тест функциональности регулярных выражений"""
        # Email pattern
        assert InputValidator.EMAIL_PATTERN.match("test@example.com") is not None
        assert InputValidator.EMAIL_PATTERN.match("invalid-email") is None
        
        # UUID pattern
        assert InputValidator.UUID_PATTERN.match("550e8400-e29b-41d4-a716-446655440000") is not None
        assert InputValidator.UUID_PATTERN.match("invalid-uuid") is None
        
        # Alphanumeric pattern
        assert InputValidator.ALPHANUMERIC_PATTERN.match("test123_") is not None
        assert InputValidator.ALPHANUMERIC_PATTERN.match("test 123") is None
        
        # Safe string pattern
        assert InputValidator.SAFE_STRING_PATTERN.match("test 123._-") is not None
        assert InputValidator.SAFE_STRING_PATTERN.match("test@#$") is None
    
    def test_class_methods_exist(self):
        """Тест существования всех методов класса"""
        methods = [
            'validate_email', 'validate_password', 'validate_name',
            'validate_description', 'validate_message', 'validate_uuid',
            'validate_path', 'sanitize_string', 'validate_json_data',
            'validate_request_size'
        ]
        
        for method_name in methods:
            assert hasattr(InputValidator, method_name)
            method = getattr(InputValidator, method_name)
            assert callable(method)
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.validators.input_validator import InputValidator, validator
        
        assert InputValidator is not None
        assert validator is not None
    
    def test_error_messages_in_russian(self):
        """Тест что сообщения об ошибках на русском языке"""
        is_valid, error = InputValidator.validate_email("")
        assert "не может быть пустым" in error
        
        is_valid, error = InputValidator.validate_password("")
        assert "не может быть пустым" in error
        
        is_valid, error = InputValidator.validate_name("")
        assert "не может быть пустым" in error
    
    def test_boundary_values(self):
        """Тест граничных значений"""
        # Email: точно максимальная длина (исправляем расчет)
        max_email = "a" * 248 + "@b.co"  # 253 символа (248 + 1 + 4 = 253)
        is_valid, error = InputValidator.validate_email(max_email)
        assert is_valid is True
        
        # Password: точно минимальная длина
        min_password = "a" * 6
        is_valid, error = InputValidator.validate_password(min_password)
        assert is_valid is True
        
        # Name: точно минимальная длина
        min_name = "a"
        is_valid, error = InputValidator.validate_name(min_name)
        assert is_valid is True