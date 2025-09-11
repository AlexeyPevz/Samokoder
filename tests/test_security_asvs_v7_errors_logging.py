"""
Тесты безопасности обработки ошибок и логирования - рефакторированная версия
Разделены на специализированные классы для лучшей организации
"""

import pytest
import time
import json
from unittest.mock import patch
from security_patches.asvs_v7_errors_logging_p0_fixes import ErrorHandlingSecurity

class BaseErrorHandlingTest:
    """Базовый класс для тестов обработки ошибок"""
    
    @pytest.fixture
    def error_handling(self):
        """Создать экземпляр ErrorHandlingSecurity"""
        return ErrorHandlingSecurity()

class TestErrorMessageSanitization(BaseErrorHandlingTest):
    """Тесты санитизации сообщений об ошибках"""
    
    def test_error_message_sanitization(self, error_handling):
        """V7.1.1: Тест санитизации сообщений об ошибках"""
        # Нормальное сообщение
        normal_message = "File not found"
        sanitized = error_handling.sanitize_error_message(normal_message)
        assert sanitized == "file not found"
        
        # Сообщение с чувствительными данными
        sensitive_message = "Invalid password for user"
        sanitized = error_handling.sanitize_error_message(sensitive_message)
        assert "[REDACTED]" in sanitized
        assert "password" not in sanitized
        
        # Сообщение с stack trace
        stack_trace = "Error in file '/path/to/file.py', line 123\nTraceback (most recent call last):"
        sanitized = error_handling.sanitize_error_message(stack_trace)
        assert "Traceback" not in sanitized
        assert "line 123" not in sanitized
        
        # Пустое сообщение
        assert error_handling.sanitize_error_message("") == "An error occurred"
        assert error_handling.sanitize_error_message(None) == "An error occurred"

class TestErrorLogging(BaseErrorHandlingTest):
    """Тесты логирования ошибок"""
    
    def test_security_event_logging(self, error_handling):
        """V7.1.2: Тест логирования событий безопасности"""
        user_id = "user123"
        details = {
            "message": "Login attempt failed",
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0"
        }
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.log_security_event("AUTHENTICATION_FAILURE", user_id, details, "WARNING")
            
            # Проверяем, что событие добавлено в лог
            assert len(error_handling.error_logs) == 1
            
            log_entry = error_handling.error_logs[0]
            assert log_entry['event_type'] == "AUTHENTICATION_FAILURE"
            assert log_entry['user_id'] == user_id
            assert log_entry['severity'] == "WARNING"
            assert log_entry['details']['message'] == "Login attempt failed"
            
            # Проверяем, что вызван logger
            mock_logger.warning.assert_called_once()

class TestErrorClassification(BaseErrorHandlingTest):
    """Тесты классификации ошибок"""
    
    def test_error_classification(self, error_handling):
        """V7.1.3: Тест классификации ошибок"""
        # Тест различных типов ошибок
        test_cases = [
            ("ValidationError", "validation_error"),
            ("AuthenticationError", "authentication_error"),
            ("PermissionError", "authorization_error"),
            ("FileNotFoundError", "file_system_error"),
            ("ConnectionError", "external_service_error"),
            ("DatabaseError", "database_error"),
            ("OpenAIError", "ai_service_error"),
            ("UnknownError", "internal_error")
        ]
        
        for error_type, expected_classification in test_cases:
            # Создаем mock исключение
            class MockException(Exception):
                pass
            
            MockException.__name__ = error_type
            
            classification = error_handling.classify_error(MockException())
            assert classification == expected_classification

class TestErrorResponse(BaseErrorHandlingTest):
    """Тесты ответов об ошибках"""
    
    def test_error_response_creation(self, error_handling):
        """V7.1.4: Тест создания ответа об ошибке"""
        error_type = "validation_error"
        message = "Invalid input data"
        details = {"field": "email", "value": "invalid-email"}
        
        response = error_handling.create_error_response(error_type, message, details)
        
        assert response["error_type"] == error_type
        assert response["message"] == message
        assert response["details"] == details
        assert "timestamp" in response
        assert "error_id" in response

class TestErrorHandlingSecurity(BaseErrorHandlingTest):
    """Основные тесты безопасности обработки ошибок"""
    
    def test_error_handling_initialization(self, error_handling):
        """V7.1.5: Тест инициализации обработчика ошибок"""
        assert hasattr(error_handling, 'error_logs')
        assert hasattr(error_handling, 'max_log_entries')
        assert error_handling.max_log_entries == 10000
        assert isinstance(error_handling.error_logs, list)