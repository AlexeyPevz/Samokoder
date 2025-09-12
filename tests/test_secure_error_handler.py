#!/usr/bin/env python3
"""
Тесты для Secure Error Handler
"""

import pytest
from unittest.mock import Mock, patch
from fastapi import Request
from fastapi.responses import JSONResponse
from backend.security.secure_error_handler import (
    ErrorSeverity, ErrorContext, SecureErrorHandler,
    secure_error_handler, create_error_context,
    handle_validation_error, handle_authentication_error,
    handle_authorization_error, handle_database_error,
    handle_encryption_error, handle_rate_limit_error,
    handle_generic_error
)


class TestSecureErrorHandler:
    """Тесты для Secure Error Handler модуля"""
    
    def test_error_severity_enum(self):
        """Тест enum уровней серьезности ошибок"""
        assert ErrorSeverity.LOW.value == "low"
        assert ErrorSeverity.MEDIUM.value == "medium"
        assert ErrorSeverity.HIGH.value == "high"
        assert ErrorSeverity.CRITICAL.value == "critical"
    
    def test_error_context_creation(self):
        """Тест создания контекста ошибки"""
        context = ErrorContext(
            error_id="test-id",
            timestamp=None,  # Будет установлено автоматически
            severity=ErrorSeverity.MEDIUM,
            user_id="user123",
            ip_address="192.168.1.1",
            user_agent="test-browser",
            endpoint="/test",
            method="GET"
        )
        
        assert context.error_id == "test-id"
        assert context.severity == ErrorSeverity.MEDIUM
        assert context.user_id == "user123"
        assert context.ip_address == "192.168.1.1"
        assert context.user_agent == "test-browser"
        assert context.endpoint == "/test"
        assert context.method == "GET"
    
    def test_secure_error_handler_init(self):
        """Тест инициализации обработчика ошибок"""
        handler = SecureErrorHandler()
        
        assert handler is not None
        assert hasattr(handler, 'safe_errors')
        assert hasattr(handler, 'unsafe_errors')
        assert hasattr(handler, 'max_error_message_length')
        
        # Проверяем что есть безопасные ошибки
        assert "validation_error" in handler.safe_errors
        assert "authentication_error" in handler.safe_errors
        assert "authorization_error" in handler.safe_errors
        
        # Проверяем что есть небезопасные ошибки
        assert "database_error" in handler.unsafe_errors
        assert "encryption_error" in handler.unsafe_errors
        assert "configuration_error" in handler.unsafe_errors
    
    def test_create_error_context(self):
        """Тест создания контекста ошибки"""
        mock_request = Mock()
        mock_request.headers = {"user-agent": "test-browser"}
        mock_request.url.path = "/test"
        mock_request.method = "GET"
        mock_request.client.host = "192.168.1.1"
        
        handler = SecureErrorHandler()
        context = handler.create_error_context(mock_request, ErrorSeverity.HIGH)
        
        assert context is not None
        assert isinstance(context.error_id, str)
        assert context.severity == ErrorSeverity.HIGH
        assert context.user_agent == "test-browser"
        assert context.endpoint == "/test"
        assert context.method == "GET"
        assert context.ip_address == "192.168.1.1"
    
    def test_get_safe_error_message(self):
        """Тест получения безопасного сообщения об ошибке"""
        handler = SecureErrorHandler()
        
        # Тестируем безопасные ошибки
        safe_message = handler._get_safe_error_message("validation_error")
        assert safe_message == "Invalid input data"
        
        # Тестируем небезопасные ошибки
        unsafe_message = handler._get_safe_error_message("database_error")
        assert unsafe_message == "Internal server error"
        
        # Тестируем неизвестную ошибку
        unknown_message = handler._get_safe_error_message("unknown_error")
        assert unknown_message == "Internal server error"
    
    def test_classify_error(self):
        """Тест классификации ошибок"""
        handler = SecureErrorHandler()
        
        # Создаем mock исключения
        class ValidationError(Exception):
            pass
        
        class AuthenticationError(Exception):
            pass
        
        class DatabaseError(Exception):
            pass
        
        class UnknownError(Exception):
            pass
        
        # Тестируем классификацию
        assert handler._classify_error(ValidationError()) == "validation_error"
        assert handler._classify_error(AuthenticationError()) == "authentication_error"
        assert handler._classify_error(DatabaseError()) == "database_error"
        assert handler._classify_error(UnknownError()) == "internal_error"
    
    def test_get_http_status_code(self):
        """Тест получения HTTP статус кодов"""
        handler = SecureErrorHandler()
        
        assert handler._get_http_status_code("validation_error") == 422
        assert handler._get_http_status_code("authentication_error") == 401
        assert handler._get_http_status_code("authorization_error") == 403
        assert handler._get_http_status_code("not_found_error") == 404
        assert handler._get_http_status_code("rate_limit_error") == 429
        assert handler._get_http_status_code("timeout_error") == 408
        assert handler._get_http_status_code("internal_error") == 500
        assert handler._get_http_status_code("unknown_error") == 500
    
    def test_get_log_level(self):
        """Тест получения уровня логирования"""
        handler = SecureErrorHandler()
        
        assert handler._get_log_level(ErrorSeverity.LOW) == 20  # INFO
        assert handler._get_log_level(ErrorSeverity.MEDIUM) == 30  # WARNING
        assert handler._get_log_level(ErrorSeverity.HIGH) == 40  # ERROR
        assert handler._get_log_level(ErrorSeverity.CRITICAL) == 50  # CRITICAL
    
    def test_get_client_ip(self):
        """Тест получения IP адреса клиента"""
        handler = SecureErrorHandler()
        
        # Тест с X-Forwarded-For
        mock_request = Mock()
        mock_request.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        
        ip = handler._get_client_ip(mock_request)
        assert ip == "192.168.1.1"
        
        # Тест с X-Real-IP
        mock_request = Mock()
        mock_request.headers = {"X-Real-IP": "192.168.1.2"}
        
        ip = handler._get_client_ip(mock_request)
        assert ip == "192.168.1.2"
        
        # Тест с client.host
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client.host = "192.168.1.3"
        
        ip = handler._get_client_ip(mock_request)
        assert ip == "192.168.1.3"
        
        # Тест без IP
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = None
        
        ip = handler._get_client_ip(mock_request)
        assert ip is None
    
    @patch('backend.security.secure_error_handler.logger')
    def test_handle_validation_error(self, mock_logger):
        """Тест обработки ошибок валидации"""
        handler = SecureErrorHandler()
        
        from datetime import datetime
        context = ErrorContext(
            error_id="test-id",
            timestamp=datetime.now(),
            severity=ErrorSeverity.MEDIUM
        )
        
        error = ValueError("Invalid input")
        response = handler.handle_validation_error(error, context)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 422
        
        response_data = response.body.decode()
        assert "validation_error" in response_data
        assert "Invalid input data" in response_data
        
        mock_logger.warning.assert_called_once()
    
    @patch('backend.security.secure_error_handler.logger')
    def test_handle_authentication_error(self, mock_logger):
        """Тест обработки ошибок аутентификации"""
        handler = SecureErrorHandler()
        
        from datetime import datetime
        context = ErrorContext(
            error_id="test-id",
            timestamp=datetime.now(),
            severity=ErrorSeverity.MEDIUM
        )
        
        error = Exception("Auth failed")
        response = handler.handle_authentication_error(error, context)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 401
        
        response_data = response.body.decode()
        assert "authentication_error" in response_data
        assert "Authentication failed" in response_data
        
        mock_logger.warning.assert_called_once()
    
    @patch('backend.security.secure_error_handler.logger')
    def test_handle_authorization_error(self, mock_logger):
        """Тест обработки ошибок авторизации"""
        handler = SecureErrorHandler()
        
        from datetime import datetime
        context = ErrorContext(
            error_id="test-id",
            timestamp=datetime.now(),
            severity=ErrorSeverity.MEDIUM
        )
        
        error = Exception("Access denied")
        response = handler.handle_authorization_error(error, context)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 403
        
        response_data = response.body.decode()
        assert "authorization_error" in response_data
        assert "Access denied" in response_data
        
        mock_logger.warning.assert_called_once()
    
    @patch('backend.security.secure_error_handler.logger')
    def test_handle_database_error(self, mock_logger):
        """Тест обработки ошибок базы данных"""
        handler = SecureErrorHandler()
        
        from datetime import datetime
        context = ErrorContext(
            error_id="test-id",
            timestamp=datetime.now(),
            severity=ErrorSeverity.HIGH
        )
        
        error = Exception("Database connection failed")
        response = handler.handle_database_error(error, context)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        
        response_data = response.body.decode()
        assert "internal_error" in response_data
        assert "Internal server error" in response_data
        
        mock_logger.error.assert_called_once()
    
    @patch('backend.security.secure_error_handler.logger')
    def test_handle_encryption_error(self, mock_logger):
        """Тест обработки ошибок шифрования"""
        handler = SecureErrorHandler()
        
        from datetime import datetime
        context = ErrorContext(
            error_id="test-id",
            timestamp=datetime.now(),
            severity=ErrorSeverity.CRITICAL
        )
        
        error = Exception("Encryption failed")
        response = handler.handle_encryption_error(error, context)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        
        response_data = response.body.decode()
        assert "internal_error" in response_data
        assert "Internal server error" in response_data
        
        mock_logger.critical.assert_called_once()
    
    @patch('backend.security.secure_error_handler.logger')
    def test_handle_rate_limit_error(self, mock_logger):
        """Тест обработки ошибок rate limiting"""
        handler = SecureErrorHandler()
        
        from datetime import datetime
        context = ErrorContext(
            error_id="test-id",
            timestamp=datetime.now(),
            severity=ErrorSeverity.MEDIUM
        )
        
        error = Exception("Rate limit exceeded")
        response = handler.handle_rate_limit_error(error, context)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 429
        
        response_data = response.body.decode()
        assert "rate_limit_error" in response_data
        assert "Too many requests" in response_data
        assert "retry_after" in response_data
        
        mock_logger.warning.assert_called_once()
    
    @patch('backend.security.secure_error_handler.logger')
    def test_handle_generic_error(self, mock_logger):
        """Тест обработки общих ошибок"""
        handler = SecureErrorHandler()
        
        from datetime import datetime
        context = ErrorContext(
            error_id="test-id",
            timestamp=datetime.now(),
            severity=ErrorSeverity.MEDIUM
        )
        
        error = Exception("Generic error")
        response = handler.handle_generic_error(error, context)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        
        response_data = response.body.decode()
        assert "internal_error" in response_data
        assert "Internal server error" in response_data
        
        mock_logger.log.assert_called_once()
    
    def test_global_instance_exists(self):
        """Тест существования глобального экземпляра"""
        assert secure_error_handler is not None
        assert isinstance(secure_error_handler, SecureErrorHandler)
    
    def test_convenience_functions(self):
        """Тест удобных функций"""
        mock_request = Mock()
        mock_request.headers = {"user-agent": "test-browser"}
        mock_request.url.path = "/test"
        mock_request.method = "GET"
        mock_request.client.host = "192.168.1.1"
        
        # Тестируем создание контекста
        context = create_error_context(mock_request, ErrorSeverity.HIGH)
        assert isinstance(context, ErrorContext)
        assert context.severity == ErrorSeverity.HIGH
        
        # Тестируем обработчики ошибок
        error = Exception("Test error")
        
        validation_response = handle_validation_error(error, context)
        assert isinstance(validation_response, JSONResponse)
        
        auth_response = handle_authentication_error(error, context)
        assert isinstance(auth_response, JSONResponse)
        
        authz_response = handle_authorization_error(error, context)
        assert isinstance(authz_response, JSONResponse)
        
        db_response = handle_database_error(error, context)
        assert isinstance(db_response, JSONResponse)
        
        enc_response = handle_encryption_error(error, context)
        assert isinstance(enc_response, JSONResponse)
        
        rate_response = handle_rate_limit_error(error, context)
        assert isinstance(rate_response, JSONResponse)
        
        generic_response = handle_generic_error(error, context)
        assert isinstance(generic_response, JSONResponse)
    
    def test_error_context_dataclass(self):
        """Тест dataclass ErrorContext"""
        # Проверяем что все поля доступны
        context = ErrorContext(
            error_id="test-id",
            timestamp=None,
            severity=ErrorSeverity.MEDIUM,
            user_id="user123",
            ip_address="192.168.1.1",
            user_agent="test-browser",
            endpoint="/test",
            method="GET"
        )
        
        # Проверяем что все поля установлены
        assert context.error_id == "test-id"
        assert context.severity == ErrorSeverity.MEDIUM
        assert context.user_id == "user123"
        assert context.ip_address == "192.168.1.1"
        assert context.user_agent == "test-browser"
        assert context.endpoint == "/test"
        assert context.method == "GET"
        
        # Проверяем что timestamp может быть None
        assert context.timestamp is None
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        # Проверяем что все компоненты доступны
        from backend.security.secure_error_handler import (
            ErrorSeverity, ErrorContext, SecureErrorHandler,
            secure_error_handler, create_error_context,
            handle_validation_error, handle_authentication_error,
            handle_authorization_error, handle_database_error,
            handle_encryption_error, handle_rate_limit_error,
            handle_generic_error
        )
        
        assert ErrorSeverity is not None
        assert ErrorContext is not None
        assert SecureErrorHandler is not None
        assert secure_error_handler is not None
        assert create_error_context is not None
        assert handle_validation_error is not None
        assert handle_authentication_error is not None
        assert handle_authorization_error is not None
        assert handle_database_error is not None
        assert handle_encryption_error is not None
        assert handle_rate_limit_error is not None
        assert handle_generic_error is not None