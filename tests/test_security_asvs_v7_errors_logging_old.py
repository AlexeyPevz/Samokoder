"""
ASVS V7: Тесты безопасности обработки ошибок и логирования
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
    pass

class TestErrorResponse(BaseErrorHandlingTest):
    """Тесты ответов об ошибках"""
    pass

class TestErrorHandlingSecurity(BaseErrorHandlingTest):
    """Основные тесты безопасности обработки ошибок"""
    
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
    
    def test_log_data_sanitization(self, error_handling):
        """V7.1.3: Тест санитизации данных для логирования"""
        sensitive_data = {
            "username": "testuser",
            "password": "secret123",
            "api_key": "abc123",
            "normal_field": "normal_value"
        }
        
        sanitized = error_handling.sanitize_log_data(sensitive_data)
        
        assert sanitized["username"] == "testuser"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["normal_field"] == "normal_value"
    
    def test_authentication_error_handling(self, error_handling):
        """V7.1.4: Тест обработки ошибок аутентификации"""
        user_id = "user123"
        error_details = {
            "message": "Invalid credentials",
            "ip_address": "192.168.1.1"
        }
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.handle_authentication_error(user_id, error_details)
            
            assert len(error_handling.error_logs) == 1
            log_entry = error_handling.error_logs[0]
            assert log_entry['event_type'] == "AUTHENTICATION_FAILURE"
            assert log_entry['severity'] == "WARNING"
            
            mock_logger.warning.assert_called_once()
    
    def test_authorization_error_handling(self, error_handling):
        """V7.1.5: Тест обработки ошибок авторизации"""
        user_id = "user123"
        error_details = {
            "message": "Access denied",
            "resource": "admin_panel"
        }
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.handle_authorization_error(user_id, error_details)
            
            assert len(error_handling.error_logs) == 1
            log_entry = error_handling.error_logs[0]
            assert log_entry['event_type'] == "AUTHORIZATION_FAILURE"
            assert log_entry['severity'] == "WARNING"
            
            mock_logger.warning.assert_called_once()
    
    def test_input_validation_error_handling(self, error_handling):
        """V7.1.6: Тест обработки ошибок валидации ввода"""
        user_id = "user123"
        error_details = {
            "message": "Invalid input format",
            "field": "email"
        }
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.handle_input_validation_error(user_id, error_details)
            
            assert len(error_handling.error_logs) == 1
            log_entry = error_handling.error_logs[0]
            assert log_entry['event_type'] == "INPUT_VALIDATION_ERROR"
            assert log_entry['severity'] == "WARNING"
            
            mock_logger.warning.assert_called_once()
    
    def test_system_error_handling(self, error_handling):
        """V7.1.7: Тест обработки системных ошибок"""
        error_details = {
            "message": "Database connection failed",
            "error_code": "DB_CONN_ERR"
        }
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.handle_system_error(error_details)
            
            assert len(error_handling.error_logs) == 1
            log_entry = error_handling.error_logs[0]
            assert log_entry['event_type'] == "SYSTEM_ERROR"
            assert log_entry['severity'] == "ERROR"
            assert log_entry['user_id'] is None
            
            mock_logger.error.assert_called_once()
    
    def test_security_violation_handling(self, error_handling):
        """V7.1.8: Тест обработки нарушений безопасности"""
        user_id = "user123"
        error_details = {
            "message": "SQL injection attempt detected",
            "payload": "'; DROP TABLE users; --"
        }
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.handle_security_violation(user_id, error_details)
            
            assert len(error_handling.error_logs) == 1
            log_entry = error_handling.error_logs[0]
            assert log_entry['event_type'] == "SECURITY_VIOLATION"
            assert log_entry['severity'] == "CRITICAL"
            
            mock_logger.critical.assert_called_once()
    
    def test_safe_error_response_creation(self, error_handling):
        """V7.1.9: Тест создания безопасного ответа об ошибке"""
        error_type = "VALIDATION_ERROR"
        user_message = "Invalid input provided"
        internal_details = {
            "user_id": "user123",
            "field": "email",
            "value": "invalid-email"
        }
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            response = error_handling.create_safe_error_response(error_type, user_message, internal_details)
            
            assert response["error"] == error_type
            assert response["message"] == "invalid input provided"
            assert "timestamp" in response
            assert "request_id" in response
            assert len(response["request_id"]) == 16
            
            mock_logger.error.assert_called_once()
    
    def test_request_id_generation(self, error_handling):
        """V7.1.10: Тест генерации ID запроса"""
        request_id1 = error_handling.generate_request_id()
        request_id2 = error_handling.generate_request_id()
        
        # ID должны быть разными
        assert request_id1 != request_id2
        
        # ID должны быть правильной длины
        assert len(request_id1) == 16
        assert len(request_id2) == 16
        
        # ID должны содержать только hex символы
        assert all(c in '0123456789abcdef' for c in request_id1)
        assert all(c in '0123456789abcdef' for c in request_id2)
    
    def test_api_access_logging(self, error_handling):
        """V7.1.11: Тест логирования доступа к API"""
        user_id = "user123"
        endpoint = "/api/projects"
        method = "GET"
        status_code = 200
        response_time = 0.5
        details = {"ip_address": "192.168.1.1"}
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.log_api_access(user_id, endpoint, method, status_code, response_time, details)
            
            assert len(error_handling.error_logs) == 1
            log_entry = error_handling.error_logs[0]
            assert log_entry['event_type'] == "API_ACCESS"
            assert log_entry['severity'] == "INFO"
            assert log_entry['details']['endpoint'] == endpoint
            assert log_entry['details']['method'] == method
            assert log_entry['details']['status_code'] == status_code
            
            mock_logger.info.assert_called_once()
    
    def test_api_access_logging_error_status(self, error_handling):
        """V7.1.11: Тест логирования доступа к API с ошибкой"""
        user_id = "user123"
        endpoint = "/api/projects"
        method = "GET"
        status_code = 500
        response_time = 2.0
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            error_handling.log_api_access(user_id, endpoint, method, status_code, response_time, {})
            
            log_entry = error_handling.error_logs[0]
            assert log_entry['severity'] == "ERROR"
            
            mock_logger.error.assert_called_once()
    
    def test_anomalous_activity_detection(self, error_handling):
        """V7.1.12: Тест обнаружения аномальной активности"""
        user_id = "user123"
        
        # Создаем несколько неудачных попыток
        for i in range(6):
            error_handling.handle_authentication_error(user_id, {"attempt": i})
        
        with patch('security_patches.asvs_v7_errors_logging_p0_fixes.logger') as mock_logger:
            activity_data = {"message": "Multiple failed attempts"}
            is_anomalous = error_handling.detect_anomalous_activity(user_id, activity_data)
            
            assert is_anomalous is True
            
            # Проверяем, что добавлен лог об аномальной активности
            anomaly_logs = [log for log in error_handling.error_logs 
                          if log['event_type'] == 'ANOMALOUS_ACTIVITY_DETECTED']
            assert len(anomaly_logs) == 1
            
            mock_logger.critical.assert_called()
    
    def test_security_logs_retrieval(self, error_handling):
        """V7.1.13: Тест получения логов безопасности"""
        user_id = "user123"
        
        # Создаем несколько логов
        error_handling.handle_authentication_error(user_id, {"message": "Auth error"})
        error_handling.handle_authorization_error(user_id, {"message": "Authz error"})
        error_handling.handle_system_error({"message": "System error"})
        
        # Получаем все логи
        all_logs = error_handling.get_security_logs()
        assert len(all_logs) == 3
        
        # Фильтруем по пользователю
        user_logs = error_handling.get_security_logs(user_id=user_id)
        assert len(user_logs) == 2
        
        # Фильтруем по типу события
        auth_logs = error_handling.get_security_logs(event_type="AUTHENTICATION_FAILURE")
        assert len(auth_logs) == 1
        
        # Фильтруем по серьезности
        warning_logs = error_handling.get_security_logs(severity="WARNING")
        assert len(warning_logs) == 2
    
    def test_old_logs_clearing(self, error_handling):
        """V7.1.14: Тест очистки старых логов"""
        # Создаем лог
        error_handling.handle_system_error({"message": "Test error"})
        assert len(error_handling.error_logs) == 1
        
        # Симулируем старый лог
        old_log = {
            "timestamp": "2020-01-01T00:00:00",
            "event_type": "OLD_EVENT",
            "severity": "INFO",
            "details": {"message": "Old message"}
        }
        error_handling.error_logs.append(old_log)
        
        # Очищаем старые логи
        cleared_count = error_handling.clear_old_logs(days=30)
        assert cleared_count == 1
        assert len(error_handling.error_logs) == 1  # Остался только новый лог
    
    def test_security_logs_export_json(self, error_handling):
        """V7.1.15: Тест экспорта логов в JSON"""
        # Создаем лог
        error_handling.handle_system_error({"message": "Test error"})
        
        # Экспортируем в JSON
        json_export = error_handling.export_security_logs("json")
        
        # Проверяем, что это валидный JSON
        parsed_logs = json.loads(json_export)
        assert len(parsed_logs) == 1
        assert parsed_logs[0]["event_type"] == "SYSTEM_ERROR"
    
    def test_security_logs_export_csv(self, error_handling):
        """V7.1.15: Тест экспорта логов в CSV"""
        # Создаем лог
        error_handling.handle_system_error({"message": "Test error"})
        
        # Экспортируем в CSV
        csv_export = error_handling.export_security_logs("csv")
        
        # Проверяем, что это валидный CSV
        lines = csv_export.strip().split('\n')
        assert len(lines) == 2  # Header + 1 data row
        assert "event_type" in lines[0]
        assert "SYSTEM_ERROR" in lines[1]
    
    def test_log_size_limit(self, error_handling):
        """V7.1.16: Тест ограничения размера лога"""
        # Создаем больше логов, чем максимальный лимит
        for i in range(error_handling.max_log_entries + 100):
            error_handling.handle_system_error({"message": f"Test error {i}"})
        
        # Проверяем, что размер лога не превышает лимит
        assert len(error_handling.error_logs) <= error_handling.max_log_entries
        
        # Проверяем, что остались последние записи
        last_log = error_handling.error_logs[-1]
        assert "Test error" in last_log["details"]["message"]
    
    def test_comprehensive_error_handling_flow(self, error_handling):
        """V7.1.17: Тест комплексного потока обработки ошибок"""
        user_id = "user123"
        
        # 1. Обрабатываем ошибку аутентификации
        error_handling.handle_authentication_error(user_id, {
            "message": "Invalid password",
            "ip_address": "192.168.1.1"
        })
        
        # 2. Создаем безопасный ответ
        response = error_handling.create_safe_error_response(
            "AUTH_ERROR",
            "Authentication failed",
            {"user_id": user_id, "password": "secret123"}
        )
        
        # 3. Проверяем, что чувствительные данные не попали в ответ
        assert "secret123" not in response["message"]
        assert "password" not in response["message"]
        
        # 4. Логируем доступ к API
        error_handling.log_api_access(user_id, "/api/login", "POST", 401, 0.1, {})
        
        # 5. Проверяем логи
        logs = error_handling.get_security_logs(user_id=user_id)
        assert len(logs) >= 2  # Аутентификация + API доступ
        
        # 6. Экспортируем логи
        json_export = error_handling.export_security_logs("json")
        assert user_id in json_export
        assert "secret123" not in json_export  # Чувствительные данные должны быть скрыты