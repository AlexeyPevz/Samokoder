"""
Тесты дополнительных компонентов безопасности
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from backend.main import app
from backend.security.input_validator import SecureInputValidator
from backend.security.session_manager import SecureSessionManager
from backend.security.file_upload_security import FileUploadSecurity
from backend.security.secure_error_handler import SecureErrorHandler, ErrorSeverity

class TestInputValidator:
    """Тесты валидатора входных данных"""
    
    def test_sql_injection_detection(self):
        """Тест обнаружения SQL injection"""
        validator = SecureInputValidator()
        
        # Безопасные запросы
        assert validator.validate_sql_input("SELECT * FROM users") == True
        assert validator.validate_sql_input("normal text") == True
        
        # SQL injection попытки
        assert validator.validate_sql_input("'; DROP TABLE users; --") == False
        assert validator.validate_sql_input("1' OR '1'='1") == False
        assert validator.validate_sql_input("admin'--") == False
        assert validator.validate_sql_input("1; DELETE FROM users;") == False
    
    def test_xss_detection(self):
        """Тест обнаружения XSS"""
        validator = SecureInputValidator()
        
        # Безопасный контент
        assert validator.validate_xss_input("Hello world") == True
        assert validator.validate_xss_input("Normal text with <b>bold</b>") == True
        
        # XSS попытки
        assert validator.validate_xss_input("<script>alert('xss')</script>") == False
        assert validator.validate_xss_input("javascript:alert('xss')") == False
        assert validator.validate_xss_input("<img src=x onerror=alert('xss')>") == False
        assert validator.validate_xss_input("<iframe src='javascript:alert(1)'></iframe>") == False
    
    def test_path_traversal_detection(self):
        """Тест обнаружения path traversal"""
        validator = SecureInputValidator()
        
        # Безопасные пути
        assert validator.validate_path_traversal("normal/path/file.txt") == True
        assert validator.validate_path_traversal("project/file.json") == True
        
        # Path traversal попытки
        assert validator.validate_path_traversal("../../../etc/passwd") == False
        assert validator.validate_path_traversal("..\\..\\windows\\system32") == False
        assert validator.validate_path_traversal("%2e%2e%2fetc%2fpasswd") == False
    
    def test_html_sanitization(self):
        """Тест санитизации HTML"""
        validator = SecureInputValidator()
        
        # Безопасный HTML
        safe_html = "<p>Hello <strong>world</strong></p>"
        sanitized = validator.sanitize_html(safe_html)
        assert "<p>" in sanitized
        assert "<strong>" in sanitized
        assert "<script>" not in sanitized
        
        # Опасный HTML
        dangerous_html = "<script>alert('xss')</script><p>Hello</p>"
        sanitized = validator.sanitize_html(dangerous_html)
        assert "<script>" not in sanitized
        assert "<p>Hello</p>" in sanitized
    
    def test_password_strength_validation(self):
        """Тест валидации силы пароля"""
        validator = SecureInputValidator()
        
        # Слабые пароли
        weak_passwords = [
            "123456",
            "password",
            "qwerty",
            "abc123",
            "Password1",  # Нет специальных символов
            "Password!",  # Нет цифр
        ]
        
        for password in weak_passwords:
            is_strong, errors = validator.validate_password_strength(password)
            assert is_strong == False
            assert len(errors) > 0
        
        # Сильный пароль
        strong_password = "MyStr0ng!P@ssw0rd"
        is_strong, errors = validator.validate_password_strength(strong_password)
        assert is_strong == True
        assert len(errors) == 0

class TestSessionManager:
    """Тесты менеджера сессий"""
    
    @pytest.mark.asyncio
    async def test_session_creation(self):
        """Тест создания сессии"""
        manager = SecureSessionManager("test-secret-key")
        
        session_id = await manager.create_session("user123", "192.168.1.1", "Mozilla/5.0")
        
        assert session_id is not None
        assert len(session_id) > 20
        assert session_id in manager.sessions
    
    @pytest.mark.asyncio
    async def test_session_validation(self):
        """Тест валидации сессии"""
        manager = SecureSessionManager("test-secret-key")
        
        # Создаем сессию
        session_id = await manager.create_session("user123", "192.168.1.1", "Mozilla/5.0")
        
        # Валидируем сессию
        assert manager.validate_session(session_id, "192.168.1.1", "Mozilla/5.0") == True
        
        # Неправильный IP
        assert manager.validate_session(session_id, "192.168.1.2", "Mozilla/5.0") == True  # IP может измениться
        
        # Неправильный User-Agent
        assert manager.validate_session(session_id, "192.168.1.1", "Chrome/91.0") == True  # User-Agent может измениться
    
    @pytest.mark.asyncio
    async def test_csrf_token_validation(self):
        """Тест валидации CSRF токена"""
        manager = SecureSessionManager("test-secret-key")
        
        # Создаем сессию
        session_id = await manager.create_session("user123", "192.168.1.1", "Mozilla/5.0")
        session_data = manager.sessions[session_id]
        
        # Валидируем правильный CSRF токен
        assert manager.validate_csrf_token(session_id, session_data.csrf_token) == True
        
        # Валидируем неправильный CSRF токен
        assert manager.validate_csrf_token(session_id, "invalid-token") == False
    
    def test_session_revocation(self):
        """Тест отзыва сессии"""
        manager = SecureSessionManager("test-secret-key")
        
        # Создаем сессию
        session_id = manager.create_session("user123", "192.168.1.1", "Mozilla/5.0")
        
        # Отзываем сессию
        assert manager.revoke_session(session_id) == True
        
        # Проверяем, что сессия больше не валидна
        assert manager.validate_session(session_id, "192.168.1.1", "Mozilla/5.0") == False
    
    def test_session_limit(self):
        """Тест лимита сессий на пользователя"""
        manager = SecureSessionManager("test-secret-key")
        manager.max_sessions_per_user = 2
        
        # Создаем максимальное количество сессий
        session1 = manager.create_session("user123", "192.168.1.1", "Mozilla/5.0")
        session2 = manager.create_session("user123", "192.168.1.2", "Chrome/91.0")
        
        # Третья сессия должна удалить самую старую
        session3 = manager.create_session("user123", "192.168.1.3", "Safari/14.0")
        
        # Первая сессия должна быть удалена
        assert session1 not in manager.sessions
        assert session2 in manager.sessions
        assert session3 in manager.sessions

class TestFileUploadSecurity:
    """Тесты безопасности загрузки файлов"""
    
    def test_file_validation(self):
        """Тест валидации файлов"""
        security = FileUploadSecurity()
        
        # Создаем тестовые файлы
        valid_image = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82'
        
        # Валидируем валидный файл
        is_valid, message, mime_type = asyncio.run(
            security.validate_file(valid_image, "test.png")
        )
        assert is_valid == True
        assert mime_type == "image/png"
        
        # Валидируем файл с запрещенным расширением
        is_valid, message, mime_type = asyncio.run(
            security.validate_file(b"test", "test.exe")
        )
        assert is_valid == False
        assert "Forbidden file extension" in message
    
    def test_file_size_validation(self):
        """Тест валидации размера файла"""
        security = FileUploadSecurity()
        
        # Создаем файл больше максимального размера
        large_file = b"x" * (11 * 1024 * 1024)  # 11 MB
        
        is_valid, message, mime_type = asyncio.run(
            security.validate_file(large_file, "large.png")
        )
        assert is_valid == False
        assert "File too large" in message
    
    def test_safe_filename_generation(self):
        """Тест генерации безопасного имени файла"""
        security = FileUploadSecurity()
        
        # Опасное имя файла
        dangerous_name = "../../../etc/passwd"
        safe_name = security._generate_safe_filename(dangerous_name)
        
        assert ".." not in safe_name
        assert "/" not in safe_name
        assert len(safe_name) <= 100

class TestSecureErrorHandler:
    """Тесты безопасного обработчика ошибок"""
    
    def test_error_classification(self):
        """Тест классификации ошибок"""
        handler = SecureErrorHandler()
        
        # Тестируем классификацию различных ошибок
        assert handler._classify_error(ValueError("test")) == "validation_error"
        assert handler._classify_error(Exception("database error")) == "internal_error"
    
    def test_safe_error_messages(self):
        """Тест безопасных сообщений об ошибках"""
        handler = SecureErrorHandler()
        
        # Безопасные ошибки
        assert handler._get_safe_error_message("validation_error") == "Invalid input data"
        assert handler._get_safe_error_message("authentication_error") == "Authentication failed"
        
        # Небезопасные ошибки
        assert handler._get_safe_error_message("database_error") == "Internal server error"
        assert handler._get_safe_error_message("encryption_error") == "Internal server error"
    
    def test_error_context_creation(self):
        """Тест создания контекста ошибки"""
        handler = SecureErrorHandler()
        
        # Создаем mock request
        request = Mock()
        request.url.path = "/api/test"
        request.method = "GET"
        request.headers = {"user-agent": "Mozilla/5.0"}
        request.client.host = "192.168.1.1"
        
        context = handler.create_error_context(request, ErrorSeverity.HIGH)
        
        assert context.error_id is not None
        assert context.endpoint == "/api/test"
        assert context.method == "GET"
        assert context.ip_address == "192.168.1.1"

class TestIntegrationSecurity:
    """Интеграционные тесты безопасности"""
    
    def test_file_upload_endpoint(self):
        """Тест endpoint загрузки файлов"""
        client = TestClient(app)
        
        # Создаем тестовый файл
        test_file = ("test.txt", b"Hello, World!", "text/plain")
        
        # Тест загрузки файла (должен вернуть ошибку авторизации)
        response = client.post(
            "/api/files/upload",
            files={"file": test_file},
            data={"project_id": "test-project"}
        )
        
        # Должен вернуть ошибку авторизации
        assert response.status_code in [401, 403]
    
    def test_input_validation_in_api(self):
        """Тест валидации входных данных в API"""
        client = TestClient(app)
        
        # Тест с опасными данными
        dangerous_data = {
            "name": "<script>alert('xss')</script>",
            "description": "'; DROP TABLE projects; --"
        }
        
        response = client.post(
            "/api/projects",
            json=dangerous_data,
            headers={"Authorization": "Bearer test-token"}
        )
        
        # Должен вернуть ошибку валидации
        assert response.status_code in [400, 401, 403]
    
    def test_security_headers(self):
        """Тест security headers"""
        client = TestClient(app)
        
        response = client.get("/api/health")
        
        # Проверяем наличие security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Strict-Transport-Security" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Permissions-Policy" in response.headers
        
        # Проверяем значения headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])