#!/usr/bin/env python3
"""
Тесты для Error Handler
"""

import pytest
from unittest.mock import Mock, patch
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from datetime import datetime
import uuid

from backend.middleware.error_handler import (
    ErrorHandler, error_handler, validation_exception_handler,
    http_exception_handler, general_exception_handler, safe_execute,
    SafeExecutionContext
)
from backend.models.responses import ErrorResponse
from backend.core.exceptions import (
    SamokoderException, AuthenticationError, AuthorizationError,
    ValidationError as SamokoderValidationError, NotFoundError,
    ConflictError, RateLimitError, AIServiceError, DatabaseError,
    ExternalServiceError
)


class TestErrorHandler:
    """Тесты для Error Handler модуля"""
    
    def test_error_handler_init(self):
        """Тест инициализации ErrorHandler"""
        handler = ErrorHandler()
        
        assert handler is not None
        assert hasattr(handler, 'error_codes')
        assert isinstance(handler.error_codes, dict)
        assert len(handler.error_codes) > 0
    
    def test_error_codes_structure(self):
        """Тест структуры кодов ошибок"""
        handler = ErrorHandler()
        
        expected_codes = [
            "validation_error", "authentication_error", "authorization_error",
            "not_found_error", "rate_limit_error", "internal_error",
            "external_service_error", "database_error", "file_system_error",
            "ai_service_error"
        ]
        
        for code in expected_codes:
            assert code in handler.error_codes
            assert isinstance(handler.error_codes[code], str)
            assert len(handler.error_codes[code]) > 0
    
    def test_handle_validation_error(self):
        """Тест обработки ошибок валидации"""
        handler = ErrorHandler()
        
        # Создаем mock ошибку валидации
        mock_exc = Mock(spec=RequestValidationError)
        mock_exc.errors.return_value = [
            {"loc": ["field1"], "msg": "Field required", "type": "value_error"}
        ]
        
        with patch('uuid.uuid4') as mock_uuid:
            mock_uuid.return_value = "test-uuid-123"
            
            response = handler.handle_validation_error(mock_exc)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        content = response.body.decode('utf-8')
        assert "validation_error" in content
        assert "test-uuid-123" in content
    
    def test_handle_http_exception(self):
        """Тест обработки HTTP исключений"""
        handler = ErrorHandler()
        
        exc = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found"
        )
        
        with patch('uuid.uuid4') as mock_uuid:
            mock_uuid.return_value = "test-uuid-456"
            
            response = handler.handle_http_exception(exc)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        
        content = response.body.decode('utf-8')
        assert "not_found_error" in content
        assert "test-uuid-456" in content
        assert "Resource not found" in content
    
    def test_handle_general_exception_samokoder(self):
        """Тест обработки Samokoder исключений"""
        handler = ErrorHandler()
        
        mock_request = Mock(spec=Request)
        
        # Создаем Samokoder исключение
        exc = AuthenticationError("Invalid credentials", details={"user_id": "123"})
        
        with patch('uuid.uuid4') as mock_uuid:
            mock_uuid.return_value = "test-uuid-789"
            
            response = handler.handle_general_exception(exc, mock_request)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        content = response.body.decode('utf-8')
        assert "AuthenticationError" in content
        assert "Invalid credentials" in content
        assert "test-uuid-789" in content
    
    def test_handle_general_exception_unknown(self):
        """Тест обработки неизвестных исключений"""
        handler = ErrorHandler()
        
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/test/path"
        mock_request.method = "GET"
        mock_request.headers.get.return_value = "Test User Agent"
        mock_request.client.host = "127.0.0.1"
        
        exc = ValueError("Test error")
        
        with patch('uuid.uuid4') as mock_uuid:
            mock_uuid.return_value = "test-uuid-999"
            
            response = handler.handle_general_exception(exc, mock_request)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        content = response.body.decode('utf-8')
        assert "internal_error" in content
        assert "test-uuid-999" in content
    
    def test_sanitize_validation_errors(self):
        """Тест санитизации ошибок валидации"""
        handler = ErrorHandler()
        
        errors = [
            {"loc": ["field1"], "msg": "Field required", "type": "value_error"},
            {"loc": ["field2"], "msg": "Invalid format", "type": "type_error"},
            {"loc": ["field3"], "msg": "Too long", "type": "length_error"}
        ]
        
        sanitized = handler._sanitize_validation_errors(errors)
        
        assert isinstance(sanitized, list)
        assert len(sanitized) == 3
        
        for i, error in enumerate(sanitized):
            assert "field" in error
            assert "message" in error
            assert "type" in error
            assert error["field"] == errors[i]["loc"]
            assert error["message"] == errors[i]["msg"]
            assert error["type"] == errors[i]["type"]
    
    def test_get_error_type_by_status(self):
        """Тест определения типа ошибки по статус коду"""
        handler = ErrorHandler()
        
        test_cases = [
            (400, "validation_error"),
            (401, "authentication_error"),
            (403, "authorization_error"),
            (404, "not_found_error"),
            (429, "rate_limit_error"),
            (500, "internal_error"),
            (502, "external_service_error"),
            (503, "external_service_error"),
            (504, "external_service_error"),
            (999, "internal_error"),  # Неизвестный код
        ]
        
        for status_code, expected_type in test_cases:
            result = handler._get_error_type_by_status(status_code)
            assert result == expected_type
    
    def test_classify_exception(self):
        """Тест классификации исключений"""
        handler = ErrorHandler()
        
        test_cases = [
            (ValidationError("test"), "validation_error"),
            (PermissionError("test"), "authorization_error"),
            (FileNotFoundError("test"), "file_system_error"),
            (ConnectionError("test"), "external_service_error"),
            (ValueError("test"), "internal_error"),  # Неизвестное исключение
        ]
        
        for exc, expected_type in test_cases:
            result = handler._classify_exception(exc)
            assert result == expected_type
    
    def test_global_error_handler_instance(self):
        """Тест глобального экземпляра обработчика ошибок"""
        assert error_handler is not None
        assert isinstance(error_handler, ErrorHandler)
    
    @pytest.mark.asyncio
    async def test_validation_exception_handler(self):
        """Тест обработчика ошибок валидации для FastAPI"""
        mock_request = Mock(spec=Request)
        mock_exc = Mock(spec=RequestValidationError)
        mock_exc.errors.return_value = []
        
        with patch.object(error_handler, 'handle_validation_error') as mock_handle:
            mock_response = Mock(spec=JSONResponse)
            mock_handle.return_value = mock_response
            
            result = await validation_exception_handler(mock_request, mock_exc)
            
            mock_handle.assert_called_once_with(mock_exc)
            assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_http_exception_handler(self):
        """Тест обработчика HTTP исключений для FastAPI"""
        mock_request = Mock(spec=Request)
        exc = HTTPException(status_code=404, detail="Not found")
        
        with patch.object(error_handler, 'handle_http_exception') as mock_handle:
            mock_response = Mock(spec=JSONResponse)
            mock_handle.return_value = mock_response
            
            result = await http_exception_handler(mock_request, exc)
            
            mock_handle.assert_called_once_with(exc)
            assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_general_exception_handler(self):
        """Тест обработчика общих исключений для FastAPI"""
        mock_request = Mock(spec=Request)
        exc = ValueError("Test error")
        
        with patch.object(error_handler, 'handle_general_exception') as mock_handle:
            mock_response = Mock(spec=JSONResponse)
            mock_handle.return_value = mock_response
            
            result = await general_exception_handler(mock_request, exc)
            
            mock_handle.assert_called_once_with(exc, mock_request)
            assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_safe_execute_decorator_success(self):
        """Тест декоратора safe_execute при успешном выполнении"""
        @safe_execute
        async def test_function():
            return "success"
        
        result = await test_function()
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_safe_execute_decorator_http_exception(self):
        """Тест декоратора safe_execute с HTTP исключением"""
        @safe_execute
        async def test_function():
            raise HTTPException(status_code=400, detail="Bad request")
        
        with pytest.raises(HTTPException) as exc_info:
            await test_function()
        
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Bad request"
    
    @pytest.mark.asyncio
    async def test_safe_execute_decorator_general_exception(self):
        """Тест декоратора safe_execute с общим исключением"""
        @safe_execute
        async def test_function():
            raise ValueError("Test error")
        
        with pytest.raises(HTTPException) as exc_info:
            await test_function()
        
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail == "Внутренняя ошибка сервера"
    
    def test_safe_execution_context_success(self):
        """Тест контекстного менеджера SafeExecutionContext при успехе"""
        with SafeExecutionContext("test_operation") as ctx:
            assert ctx.operation_name == "test_operation"
            assert ctx.error_id is not None
        
        # Контекст должен завершиться без ошибок
        assert True
    
    def test_safe_execution_context_exception(self):
        """Тест контекстного менеджера SafeExecutionContext с исключением"""
        with pytest.raises(ValueError):
            with SafeExecutionContext("test_operation") as ctx:
                assert ctx.operation_name == "test_operation"
                raise ValueError("Test error")
        
        # Исключение должно быть переброшено
        assert True
    
    def test_error_response_structure(self):
        """Тест структуры ErrorResponse"""
        handler = ErrorHandler()
        exc = HTTPException(status_code=400, detail="Bad request")
        
        response = handler.handle_http_exception(exc)
        content = response.body.decode('utf-8')
        
        # Проверяем что ответ содержит необходимые поля
        assert "error" in content
        assert "message" in content
        assert "details" in content
    
    def test_logging_in_error_handling(self):
        """Тест логирования в обработке ошибок"""
        handler = ErrorHandler()
        
        with patch('logging.getLogger') as mock_logger:
            mock_logger_instance = Mock()
            mock_logger.return_value = mock_logger_instance
            
            exc = HTTPException(status_code=500, detail="Internal error")
            response = handler.handle_http_exception(exc)
            
            # Проверяем что логирование было вызвано
            mock_logger_instance.error.assert_called_once()
    
    def test_uuid_generation_in_errors(self):
        """Тест генерации UUID в ошибках"""
        handler = ErrorHandler()
        
        with patch('uuid.uuid4') as mock_uuid:
            mock_uuid.return_value = "fixed-uuid-123"
            
            exc = HTTPException(status_code=404, detail="Not found")
            response = handler.handle_http_exception(exc)
            
            content = response.body.decode('utf-8')
            assert "fixed-uuid-123" in content
    
    def test_error_handler_methods_exist(self):
        """Тест существования всех методов ErrorHandler"""
        handler = ErrorHandler()
        
        methods = [
            'handle_validation_error', 'handle_http_exception', 
            'handle_general_exception', '_sanitize_validation_errors',
            '_get_error_type_by_status', '_classify_exception'
        ]
        
        for method_name in methods:
            assert hasattr(handler, method_name)
            method = getattr(handler, method_name)
            assert callable(method)
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.middleware.error_handler import (
            ErrorHandler, error_handler, validation_exception_handler,
            http_exception_handler, general_exception_handler, safe_execute,
            SafeExecutionContext
        )
        
        assert ErrorHandler is not None
        assert error_handler is not None
        assert validation_exception_handler is not None
        assert http_exception_handler is not None
        assert general_exception_handler is not None
        assert safe_execute is not None
        assert SafeExecutionContext is not None
    
    def test_error_codes_are_strings(self):
        """Тест что коды ошибок являются строками"""
        handler = ErrorHandler()
        
        for code, message in handler.error_codes.items():
            assert isinstance(code, str)
            assert isinstance(message, str)
            assert len(code) > 0
            assert len(message) > 0
    
    def test_status_code_mapping_completeness(self):
        """Тест полноты маппинга статус кодов"""
        handler = ErrorHandler()
        
        # Проверяем что все основные HTTP коды покрыты
        test_codes = [400, 401, 403, 404, 429, 500, 502, 503, 504]
        
        for code in test_codes:
            error_type = handler._get_error_type_by_status(code)
            assert error_type in handler.error_codes
    
    def test_exception_classification_keywords(self):
        """Тест ключевых слов в классификации исключений"""
        handler = ErrorHandler()
        
        # Тестируем различные типы исключений
        test_exceptions = [
            (ValidationError("test"), "validation_error"),
            (PermissionError("test"), "authorization_error"),
            (FileNotFoundError("test"), "file_system_error"),
            (OSError("test"), "file_system_error"),
            (ConnectionError("test"), "external_service_error"),
            (TimeoutError("test"), "external_service_error"),
        ]
        
        for exc, expected_type in test_exceptions:
            result = handler._classify_exception(exc)
            assert result == expected_type