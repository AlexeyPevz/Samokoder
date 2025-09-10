"""
ASVS V12: Тесты безопасности API
"""
import pytest
import time
from unittest.mock import Mock
from security_patches.asvs_v12_api_security_p0_fixes import APISecurity

class TestAPISecurity:
    """Тесты безопасности API"""
    
    @pytest.fixture
    def api_security(self):
        """Создать экземпляр APISecurity"""
        return APISecurity()
    
    def test_api_endpoint_validation(self, api_security):
        """V12.1.1: Тест валидации API endpoint"""
        # Валидные endpoints
        assert api_security.validate_api_endpoint("/api/users", "GET") is True
        assert api_security.validate_api_endpoint("/api/projects/123", "POST") is True
        
        # Невалидные endpoints
        assert api_security.validate_api_endpoint("", "GET") is False
        assert api_security.validate_api_endpoint("/api/users", "") is False
        assert api_security.validate_api_endpoint("api/users", "GET") is False
        assert api_security.validate_api_endpoint("/api/users<script>", "GET") is False
        assert api_security.validate_api_endpoint("/api/users", "INVALID") is False
    
    def test_request_headers_validation(self, api_security):
        """V12.1.2: Тест валидации заголовков запроса"""
        # Валидные заголовки
        valid_headers = {
            "content-type": "application/json",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        issues = api_security.validate_request_headers(valid_headers)
        assert len(issues) == 0
        
        # Невалидные заголовки
        invalid_headers = {
            "content-type": "text/html",
            "user-agent": "a" * 1000
        }
        issues = api_security.validate_request_headers(invalid_headers)
        assert len(issues) > 0
    
    def test_request_body_validation(self, api_security):
        """V12.1.3: Тест валидации тела запроса"""
        # Валидное тело запроса
        valid_body = '{"name": "test", "value": 123}'
        issues = api_security.validate_request_body(valid_body, "application/json")
        assert len(issues) == 0
        
        # Невалидное тело запроса
        invalid_body = "<script>alert('xss')</script>"
        issues = api_security.validate_request_body(invalid_body, "application/json")
        assert len(issues) > 0
        
        # Слишком большое тело запроса
        large_body = "a" * (11 * 1024 * 1024)  # 11MB
        issues = api_security.validate_request_body(large_body, "application/json")
        assert any("too large" in issue for issue in issues)
    
    def test_query_parameters_validation(self, api_security):
        """V12.1.4: Тест валидации параметров запроса"""
        # Валидные параметры
        valid_params = {"name": "test", "value": "123"}
        issues = api_security.validate_query_parameters(valid_params)
        assert len(issues) == 0
        
        # Невалидные параметры
        invalid_params = {"name": "<script>alert('xss')</script>", "value": "a" * 2000}
        issues = api_security.validate_query_parameters(invalid_params)
        assert len(issues) > 0
    
    def test_rate_limiting(self, api_security):
        """V12.1.5: Тест rate limiting"""
        client_ip = "192.168.1.1"
        endpoint = "/api/test"
        method = "GET"
        
        # Первые 100 запросов должны проходить
        for i in range(100):
            assert api_security.check_rate_limit(client_ip, endpoint, method) is True
        
        # 101-й запрос должен быть заблокирован
        assert api_security.check_rate_limit(client_ip, endpoint, method) is False
    
    def test_brute_force_detection(self, api_security):
        """V12.1.6: Тест обнаружения brute force атак"""
        client_ip = "192.168.1.1"
        endpoint = "/api/auth/login"
        
        # Первые 20 запросов должны проходить
        for i in range(20):
            assert api_security.detect_brute_force_attack(client_ip, endpoint) is False
        
        # 21-й запрос должен быть обнаружен как brute force
        assert api_security.detect_brute_force_attack(client_ip, endpoint) is True
    
    def test_api_key_validation(self, api_security):
        """V12.1.7: Тест валидации API ключа"""
        # Валидный API ключ
        valid_key = "sk-1234567890abcdef1234567890abcdef"
        assert api_security.validate_api_key(valid_key) is True
        
        # Невалидные API ключи
        assert api_security.validate_api_key("") is False
        assert api_security.validate_api_key("short") is False
        assert api_security.validate_api_key("key with spaces") is False
        assert api_security.validate_api_key("key@with#special$chars") is False
    
    def test_api_response_sanitization(self, api_security):
        """V12.1.8: Тест санитизации ответа API"""
        # Санитизация строки
        dangerous_string = "Hello <script>alert('xss')</script> world"
        sanitized = api_security.sanitize_api_response(dangerous_string)
        assert "<script>" not in sanitized
        assert "alert" not in sanitized
        
        # Санитизация словаря
        dangerous_dict = {
            "name": "test",
            "content": "<script>alert('xss')</script>",
            "nested": {
                "value": "safe value",
                "dangerous": "<iframe src='evil.com'></iframe>"
            }
        }
        sanitized = api_security.sanitize_api_response(dangerous_dict)
        assert "<script>" not in str(sanitized)
        assert "<iframe>" not in str(sanitized)
    
    def test_cors_origin_validation(self, api_security):
        """V12.1.9: Тест валидации CORS origin"""
        allowed_origins = ["https://example.com", "https://*.example.com"]
        
        # Валидные origins
        assert api_security.validate_cors_origin("https://example.com", allowed_origins) is True
        assert api_security.validate_cors_origin("https://sub.example.com", allowed_origins) is True
        
        # Невалидные origins
        assert api_security.validate_cors_origin("", allowed_origins) is False
        assert api_security.validate_cors_origin("https://evil.com", allowed_origins) is False
        assert api_security.validate_cors_origin("http://example.com", allowed_origins) is False
    
    def test_sql_injection_detection(self, api_security):
        """V12.1.10: Тест обнаружения SQL injection"""
        # SQL injection атаки
        sql_attacks = [
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users--",
            "admin' OR '1'='1",
            "'; EXEC xp_cmdshell('dir'); --"
        ]
        
        for attack in sql_attacks:
            assert api_security.detect_sql_injection(attack) is True
        
        # Нормальный ввод
        normal_input = "John Doe"
        assert api_security.detect_sql_injection(normal_input) is False
    
    def test_xss_attack_detection(self, api_security):
        """V12.1.11: Тест обнаружения XSS атак"""
        # XSS атаки
        xss_attacks = [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert('xss')",
            "<iframe src='evil.com'></iframe>"
        ]
        
        for attack in xss_attacks:
            assert api_security.detect_xss_attack(attack) is True
        
        # Нормальный ввод
        normal_input = "Hello, world!"
        assert api_security.detect_xss_attack(normal_input) is False
    
    def test_file_upload_validation(self, api_security):
        """V12.1.12: Тест валидации загрузки файлов"""
        # Валидная загрузка файла
        issues = api_security.validate_file_upload("test.txt", 1024, "text/plain")
        assert len(issues) == 0
        
        # Невалидные загрузки файлов
        issues = api_security.validate_file_upload("", 1024, "text/plain")
        assert len(issues) > 0
        
        issues = api_security.validate_file_upload("test.exe", 1024, "application/octet-stream")
        assert len(issues) > 0
        
        issues = api_security.validate_file_upload("test.txt", 20*1024*1024, "text/plain")
        assert any("too large" in issue for issue in issues)
    
    def test_ip_blocking(self, api_security):
        """V12.1.14-16: Тест блокировки IP"""
        ip = "192.168.1.100"
        
        # IP не заблокирован
        assert api_security.is_ip_blocked(ip) is False
        
        # Блокируем IP
        api_security.block_suspicious_ip(ip, "Multiple failed login attempts")
        assert api_security.is_ip_blocked(ip) is True
        
        # Разблокируем IP
        api_security.unblock_ip(ip)
        assert api_security.is_ip_blocked(ip) is False
    
    def test_comprehensive_api_security_flow(self, api_security):
        """V12.1.17: Тест комплексного потока безопасности API"""
        # Создаем mock request
        request = Mock()
        request.client.host = "192.168.1.1"
        request.url.path = "/api/test"
        request.method = "GET"
        request.headers = {
            "user-agent": "Mozilla/5.0",
            "content-type": "application/json"
        }
        
        # 1. Валидируем endpoint
        assert api_security.validate_api_endpoint(str(request.url.path), request.method) is True
        
        # 2. Валидируем заголовки
        header_issues = api_security.validate_request_headers(dict(request.headers))
        assert len(header_issues) == 0
        
        # 3. Проверяем rate limiting
        assert api_security.check_rate_limit(request.client.host, str(request.url.path), request.method) is True
        
        # 4. Генерируем отчет по безопасности
        report = api_security.generate_api_security_report(request, 200, 0.5)
        assert report["client_ip"] == "192.168.1.1"
        assert report["endpoint"] == "/api/test"
        assert report["method"] == "GET"
        assert report["status_code"] == 200
        assert "security_checks" in report