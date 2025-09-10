"""
ASVS V5: Тесты безопасности валидации и кодирования
"""
import pytest
import json
import base64
from security_patches.asvs_v5_validation_p0_fixes import ValidationSecurity

class TestValidationSecurity:
    """Тесты безопасности валидации и кодирования"""
    
    @pytest.fixture
    def validation_security(self):
        """Создать экземпляр ValidationSecurity"""
        return ValidationSecurity()
    
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
        assert validation_security.validate_input_length("test", max_length=2) is False
    
    def test_html_input_sanitization(self, validation_security):
        """V5.1.2: Тест санитизации HTML ввода"""
        # Нормальный текст
        normal_text = "Hello, world!"
        assert validation_security.sanitize_html_input(normal_text) == "Hello, world!"
        
        # XSS атака
        xss_input = "<script>alert('xss')</script>"
        sanitized = validation_security.sanitize_html_input(xss_input)
        assert "<script>" not in sanitized
        assert "alert" not in sanitized
        
        # HTML теги
        html_input = "<p>Hello <b>world</b></p>"
        sanitized = validation_security.sanitize_html_input(html_input)
        assert "<p>" not in sanitized
        assert "<b>" not in sanitized
        assert "Hello" in sanitized
        assert "world" in sanitized
        
        # JavaScript события
        js_input = "<img src='x' onerror='alert(1)'>"
        sanitized = validation_security.sanitize_html_input(js_input)
        assert "onerror" not in sanitized
        assert "alert" not in sanitized
    
    def test_email_format_validation(self, validation_security):
        """V5.1.3: Тест валидации формата email"""
        # Валидные email
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "user+tag@example.org",
            "user123@test-domain.com"
        ]
        
        for email in valid_emails:
            assert validation_security.validate_email_format(email) is True
        
        # Невалидные email
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "test@",
            "test..test@example.com",
            "test@.com",
            "test@example.",
            ""
        ]
        
        for email in invalid_emails:
            assert validation_security.validate_email_format(email) is False
    
    def test_url_format_validation(self, validation_security):
        """V5.1.4: Тест валидации формата URL"""
        # Валидные URL
        valid_urls = [
            "https://example.com",
            "http://test.org",
            "https://subdomain.example.com/path",
            "http://example.com:8080/path?param=value"
        ]
        
        for url in valid_urls:
            assert validation_security.validate_url_format(url) is True
        
        # Невалидные URL
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            ""
        ]
        
        for url in invalid_urls:
            assert validation_security.validate_url_format(url) is False
    
    def test_json_input_validation(self, validation_security):
        """V5.1.5: Тест валидации JSON ввода"""
        # Валидный JSON
        valid_json = '{"key": "value", "number": 123}'
        assert validation_security.validate_json_input(valid_json) is True
        
        # Невалидный JSON
        invalid_json = '{"key": "value", "number": 123'  # Отсутствует закрывающая скобка
        assert validation_security.validate_json_input(invalid_json) is False
        
        # Пустой JSON
        assert validation_security.validate_json_input("") is False
        assert validation_security.validate_json_input(None) is False
    
    def test_sql_input_sanitization(self, validation_security):
        """V5.1.6: Тест санитизации SQL ввода"""
        # Нормальный ввод
        normal_input = "SELECT * FROM users"
        sanitized = validation_security.sanitize_sql_input(normal_input)
        assert "SELECT" in sanitized
        assert "*" in sanitized
        
        # SQL injection
        sql_injection = "'; DROP TABLE users; --"
        sanitized = validation_security.sanitize_sql_input(sql_injection)
        assert "DROP" not in sanitized
        assert "--" not in sanitized
        assert ";" not in sanitized
    
    def test_file_upload_validation(self, validation_security):
        """V5.1.7: Тест валидации загрузки файла"""
        # Валидный файл
        assert validation_security.validate_file_upload("test.txt", 1024, "text/plain") is True
        
        # Невалидные файлы
        assert validation_security.validate_file_upload("", 1024, "text/plain") is False
        assert validation_security.validate_file_upload("test.txt", 0, "text/plain") is False
        assert validation_security.validate_file_upload("test.exe", 1024, "application/octet-stream") is False
        assert validation_security.validate_file_upload("test.txt", 20*1024*1024, "text/plain") is False  # Слишком большой
    
    def test_html_output_encoding(self, validation_security):
        """V5.1.8: Тест кодирования вывода для HTML"""
        # Нормальный текст
        normal_text = "Hello, world!"
        encoded = validation_security.encode_output_for_html(normal_text)
        assert encoded == "Hello, world!"
        
        # HTML символы
        html_text = "<script>alert('xss')</script>"
        encoded = validation_security.encode_output_for_html(html_text)
        assert "&lt;" in encoded
        assert "&gt;" in encoded
        assert "&quot;" in encoded
        assert "&#x27;" in encoded
    
    def test_url_output_encoding(self, validation_security):
        """V5.1.9: Тест кодирования вывода для URL"""
        # Нормальный текст
        normal_text = "hello world"
        encoded = validation_security.encode_output_for_url(normal_text)
        assert encoded == "hello%20world"
        
        # Специальные символы
        special_text = "test@example.com"
        encoded = validation_security.encode_output_for_url(special_text)
        assert "@" not in encoded
        assert "." not in encoded
    
    def test_json_output_encoding(self, validation_security):
        """V5.1.10: Тест кодирования вывода для JSON"""
        # Нормальные данные
        data = {"key": "value", "number": 123}
        encoded = validation_security.encode_output_for_json(data)
        assert '"key":"value"' in encoded
        assert '"number":123' in encoded
        
        # Специальные символы
        data = {"key": "value with \"quotes\""}
        encoded = validation_security.encode_output_for_json(data)
        assert '\\"' in encoded
    
    def test_numeric_input_validation(self, validation_security):
        """V5.1.11: Тест валидации числового ввода"""
        # Валидные числа
        assert validation_security.validate_numeric_input("123") is True
        assert validation_security.validate_numeric_input(123) is True
        assert validation_security.validate_numeric_input(123.45) is True
        
        # Невалидные числа
        assert validation_security.validate_numeric_input("abc") is False
        assert validation_security.validate_numeric_input("") is False
        assert validation_security.validate_numeric_input(None) is False
        
        # С ограничениями
        assert validation_security.validate_numeric_input("50", min_val=0, max_val=100) is True
        assert validation_security.validate_numeric_input("150", min_val=0, max_val=100) is False
        assert validation_security.validate_numeric_input("-10", min_val=0, max_val=100) is False
    
    def test_alpha_numeric_input_validation(self, validation_security):
        """V5.1.12: Тест валидации алфавитно-цифрового ввода"""
        # Валидный ввод
        assert validation_security.validate_alpha_numeric_input("abc123") is True
        assert validation_security.validate_alpha_numeric_input("ABC123") is True
        assert validation_security.validate_alpha_numeric_input("") is True
        
        # Невалидный ввод
        assert validation_security.validate_alpha_numeric_input("abc 123") is False
        assert validation_security.validate_alpha_numeric_input("abc-123") is False
        assert validation_security.validate_alpha_numeric_input("abc@123") is False
        
        # С разрешенными пробелами
        assert validation_security.validate_alpha_numeric_input("abc 123", allow_spaces=True) is True
    
    def test_path_input_sanitization(self, validation_security):
        """V5.1.13: Тест санитизации пути"""
        # Нормальный путь
        normal_path = "folder/file.txt"
        sanitized = validation_security.sanitize_path_input(normal_path)
        assert sanitized == "folder/file.txt"
        
        # Опасный путь
        dangerous_path = "../../../etc/passwd"
        sanitized = validation_security.sanitize_path_input(dangerous_path)
        assert ".." not in sanitized
        
        # Путь с ведущими слешами
        path_with_slashes = "///folder/file.txt"
        sanitized = validation_security.sanitize_path_input(path_with_slashes)
        assert not sanitized.startswith("/")
    
    def test_base64_input_validation(self, validation_security):
        """V5.1.14: Тест валидации Base64 ввода"""
        # Валидный Base64
        valid_base64 = base64.b64encode(b"Hello, world!").decode('utf-8')
        assert validation_security.validate_base64_input(valid_base64) is True
        
        # Невалидный Base64
        assert validation_security.validate_base64_input("invalid base64!") is False
        assert validation_security.validate_base64_input("") is False
        assert validation_security.validate_base64_input(None) is False
    
    def test_injection_attack_prevention(self, validation_security):
        """V5.1.15: Тест предотвращения injection атак"""
        # XSS атака
        xss_input = "<script>alert('xss')</script>"
        sanitized = validation_security.prevent_injection_attacks(xss_input)
        assert "<script>" not in sanitized
        assert "alert" not in sanitized
        
        # CSS injection
        css_input = "expression(alert('xss'))"
        sanitized = validation_security.prevent_injection_attacks(css_input)
        assert "expression" not in sanitized
        
        # JavaScript URL
        js_url = "javascript:alert('xss')"
        sanitized = validation_security.prevent_injection_attacks(js_url)
        assert "javascript:" not in sanitized
        
        # Data URL
        data_url = "data:text/html,<script>alert('xss')</script>"
        sanitized = validation_security.prevent_injection_attacks(data_url)
        assert "data:" not in sanitized
        assert "<script>" not in sanitized
    
    def test_comprehensive_validation_flow(self, validation_security):
        """V5.1.16: Тест комплексного потока валидации"""
        # Тестовые данные
        user_input = "<script>alert('xss')</script>Hello, world!"
        
        # 1. Проверка длины
        assert validation_security.validate_input_length(user_input) is True
        
        # 2. Санитизация HTML
        sanitized_html = validation_security.sanitize_html_input(user_input)
        assert "<script>" not in sanitized_html
        
        # 3. Предотвращение injection атак
        final_sanitized = validation_security.prevent_injection_attacks(sanitized_html)
        assert "alert" not in final_sanitized
        
        # 4. Кодирование для HTML вывода
        encoded_output = validation_security.encode_output_for_html(final_sanitized)
        assert "&lt;" in encoded_output or "&gt;" in encoded_output
    
    def test_edge_cases(self, validation_security):
        """V5.1.17: Тест граничных случаев"""
        # None значения
        assert validation_security.validate_input_length(None) is True
        assert validation_security.sanitize_html_input(None) == ""
        assert validation_security.validate_email_format(None) is False
        
        # Пустые строки
        assert validation_security.validate_input_length("") is True
        assert validation_security.sanitize_html_input("") == ""
        assert validation_security.validate_email_format("") is False
        
        # Очень длинные строки
        very_long_string = "a" * 100000
        assert validation_security.validate_input_length(very_long_string) is False
        
        # Специальные символы
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        sanitized = validation_security.sanitize_html_input(special_chars)
        assert "&" in sanitized  # Должно быть закодировано
        assert "<" in sanitized  # Должно быть закодировано
        assert ">" in sanitized  # Должно быть закодировано