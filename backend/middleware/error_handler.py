"""
Централизованная обработка ошибок для FastAPI
Предотвращает утечки внутренней информации
"""

import logging
import traceback
import uuid
from datetime import datetime
from typing import Dict, Any
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
import sys

from backend.models.responses import ErrorResponse

logger = logging.getLogger(__name__)

class ErrorHandler:
    """Централизованный обработчик ошибок"""
    
    def __init__(self):
        self.error_codes = {
            "validation_error": "Ошибка валидации входных данных",
            "authentication_error": "Ошибка аутентификации",
            "authorization_error": "Ошибка авторизации",
            "not_found_error": "Ресурс не найден",
            "rate_limit_error": "Превышен лимит запросов",
            "internal_error": "Внутренняя ошибка сервера",
            "external_service_error": "Ошибка внешнего сервиса",
            "database_error": "Ошибка базы данных",
            "file_system_error": "Ошибка файловой системы",
            "ai_service_error": "Ошибка AI сервиса"
        }
    
    def handle_validation_error(self, exc: RequestValidationError) -> JSONResponse:
        """Обработка ошибок валидации Pydantic"""
        error_id = str(uuid.uuid4())
        
        # Логируем детали для разработки
        logger.warning(f"Validation error {error_id}: {exc.errors()}")
        
        # Возвращаем безопасный ответ
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error="validation_error",
                message="Ошибка валидации входных данных",
                details={
                    "error_id": error_id,
                    "field_errors": self._sanitize_validation_errors(exc.errors())
                }
            ).dict()
        )
    
    def handle_http_exception(self, exc: HTTPException) -> JSONResponse:
        """Обработка HTTP исключений"""
        error_id = str(uuid.uuid4())
        
        # Логируем ошибку
        logger.error(f"HTTP error {error_id}: {exc.status_code} - {exc.detail}")
        
        # Определяем тип ошибки по статус коду
        error_type = self._get_error_type_by_status(exc.status_code)
        
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=error_type,
                message=str(exc.detail),
                details={"error_id": error_id}
            ).dict()
        )
    
    def handle_general_exception(self, exc: Exception, request: Request) -> JSONResponse:
        """Обработка общих исключений"""
        error_id = str(uuid.uuid4())
        
        # Логируем полную информацию об ошибке
        logger.error(
            f"Unexpected error {error_id}: {type(exc).__name__}: {exc}",
            exc_info=True,
            extra={
                "error_id": error_id,
                "request_path": request.url.path,
                "request_method": request.method,
                "user_agent": request.headers.get("user-agent"),
                "client_ip": request.client.host if request.client else None
            }
        )
        
        # Определяем тип ошибки
        error_type = self._classify_exception(exc)
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error=error_type,
                message="Внутренняя ошибка сервера",
                details={
                    "error_id": error_id,
                    "timestamp": datetime.now().isoformat()
                }
            ).dict()
        )
    
    def _sanitize_validation_errors(self, errors: list) -> list:
        """Очищает ошибки валидации от чувствительной информации"""
        sanitized = []
        for error in errors:
            sanitized_error = {
                "field": error.get("loc", []),
                "message": error.get("msg", "Validation error"),
                "type": error.get("type", "value_error")
            }
            sanitized.append(sanitized_error)
        return sanitized
    
    def _get_error_type_by_status(self, status_code: int) -> str:
        """Определяет тип ошибки по HTTP статус коду"""
        error_mapping = {
            400: "validation_error",
            401: "authentication_error",
            403: "authorization_error",
            404: "not_found_error",
            429: "rate_limit_error",
            500: "internal_error",
            502: "external_service_error",
            503: "external_service_error",
            504: "external_service_error"
        }
        return error_mapping.get(status_code, "internal_error")
    
    def _classify_exception(self, exc: Exception) -> str:
        """Классифицирует исключение по типу"""
        exception_type = type(exc).__name__
        
        if "ValidationError" in exception_type:
            return "validation_error"
        elif "AuthenticationError" in exception_type or "Unauthorized" in exception_type:
            return "authentication_error"
        elif "PermissionError" in exception_type or "Forbidden" in exception_type:
            return "authorization_error"
        elif "FileNotFoundError" in exception_type or "OSError" in exception_type:
            return "file_system_error"
        elif "ConnectionError" in exception_type or "TimeoutError" in exception_type:
            return "external_service_error"
        elif "DatabaseError" in exception_type or "IntegrityError" in exception_type:
            return "database_error"
        elif "AI" in exception_type or "OpenAI" in exception_type or "Anthropic" in exception_type:
            return "ai_service_error"
        else:
            return "internal_error"

# Глобальный экземпляр обработчика ошибок
error_handler = ErrorHandler()

# Функции для использования в FastAPI
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Обработчик ошибок валидации для FastAPI"""
    return error_handler.handle_validation_error(exc)

async def http_exception_handler(request: Request, exc: HTTPException):
    """Обработчик HTTP исключений для FastAPI"""
    return error_handler.handle_http_exception(exc)

async def general_exception_handler(request: Request, exc: Exception):
    """Обработчик общих исключений для FastAPI"""
    return error_handler.handle_general_exception(exc, request)

# Декоратор для безопасной обработки ошибок в функциях
def safe_execute(func):
    """Декоратор для безопасного выполнения функций"""
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except HTTPException:
            raise  # Перебрасываем HTTP исключения
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error(f"Error in {func.__name__} {error_id}: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Внутренняя ошибка сервера"
            )
    return wrapper

# Контекстный менеджер для безопасного выполнения
class SafeExecutionContext:
    """Контекстный менеджер для безопасного выполнения кода"""
    
    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.error_id = str(uuid.uuid4())
    
    def __enter__(self):
        logger.debug(f"Starting {self.operation_name} (ID: {self.error_id})")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            logger.error(
                f"Error in {self.operation_name} (ID: {self.error_id}): {exc_val}",
                exc_info=(exc_type, exc_val, exc_tb)
            )
            return False  # Не подавляем исключение
        else:
            logger.debug(f"Completed {self.operation_name} (ID: {self.error_id})")
            return False