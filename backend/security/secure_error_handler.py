"""
Безопасная обработка ошибок
Предотвращает information disclosure
"""

import logging
import traceback
import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Уровни серьезности ошибок"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ErrorContext:
    """Контекст ошибки"""
    error_id: str
    timestamp: datetime
    severity: ErrorSeverity
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None

class SecureErrorHandler:
    """Безопасный обработчик ошибок"""
    
    def __init__(self):
        # Ошибки, которые можно показывать пользователю
        self.safe_errors = {
            "validation_error": "Invalid input data",
            "authentication_error": "Authentication failed",
            "authorization_error": "Access denied",
            "not_found_error": "Resource not found",
            "rate_limit_error": "Too many requests",
            "file_too_large": "File size exceeds limit",
            "unsupported_file_type": "File type not supported",
        }
        
        # Ошибки, которые нужно скрывать
        self.unsafe_errors = {
            "database_error": "Internal server error",
            "encryption_error": "Internal server error",
            "configuration_error": "Internal server error",
            "network_error": "Service temporarily unavailable",
            "timeout_error": "Request timeout",
            "memory_error": "Internal server error",
            "permission_error": "Internal server error",
        }
        
        # Максимальная длина сообщения об ошибке
        self.max_error_message_length = 200
    
    def create_error_context(self, request: Request, severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> ErrorContext:
        """Создает контекст ошибки"""
        return ErrorContext(
            error_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity=severity,
            ip_address=self._get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            endpoint=str(request.url.path),
            method=request.method
        )
    
    def handle_validation_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Обрабатывает ошибки валидации"""
        error_message = self._get_safe_error_message("validation_error")
        
        # Логируем детали для разработки
        logger.warning(
            f"Validation error {context.error_id}",
            extra={
                "error_id": context.error_id,
                "error_type": "validation_error",
                "severity": context.severity.value,
                "endpoint": context.endpoint,
                "method": context.method,
                "user_id": context.user_id,
                "ip_address": context.ip_address,
                "error_details": str(error)[:self.max_error_message_length]
            }
        )
        
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": error_message,
                "error_id": context.error_id,
                "timestamp": context.timestamp.isoformat()
            }
        )
    
    def handle_authentication_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Обрабатывает ошибки аутентификации"""
        error_message = self._get_safe_error_message("authentication_error")
        
        # Логируем попытку аутентификации
        logger.warning(
            f"Authentication failed {context.error_id}",
            extra={
                "error_id": context.error_id,
                "error_type": "authentication_error",
                "severity": context.severity.value,
                "endpoint": context.endpoint,
                "method": context.method,
                "ip_address": context.ip_address,
                "user_agent": context.user_agent
            }
        )
        
        return JSONResponse(
            status_code=401,
            content={
                "error": "authentication_error",
                "message": error_message,
                "error_id": context.error_id,
                "timestamp": context.timestamp.isoformat()
            }
        )
    
    def handle_authorization_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Обрабатывает ошибки авторизации"""
        error_message = self._get_safe_error_message("authorization_error")
        
        # Логируем попытку несанкционированного доступа
        logger.warning(
            f"Authorization failed {context.error_id}",
            extra={
                "error_id": context.error_id,
                "error_type": "authorization_error",
                "severity": context.severity.value,
                "endpoint": context.endpoint,
                "method": context.method,
                "user_id": context.user_id,
                "ip_address": context.ip_address
            }
        )
        
        return JSONResponse(
            status_code=403,
            content={
                "error": "authorization_error",
                "message": error_message,
                "error_id": context.error_id,
                "timestamp": context.timestamp.isoformat()
            }
        )
    
    def handle_database_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Обрабатывает ошибки базы данных"""
        error_message = self._get_safe_error_message("database_error")
        
        # Логируем детали для администраторов
        logger.error(
            f"Database error {context.error_id}",
            extra={
                "error_id": context.error_id,
                "error_type": "database_error",
                "severity": context.severity.value,
                "endpoint": context.endpoint,
                "method": context.method,
                "user_id": context.user_id,
                "ip_address": context.ip_address,
                "error_details": str(error),
                "traceback": traceback.format_exc()
            }
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": error_message,
                "error_id": context.error_id,
                "timestamp": context.timestamp.isoformat()
            }
        )
    
    def handle_encryption_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Обрабатывает ошибки шифрования"""
        error_message = self._get_safe_error_message("encryption_error")
        
        # Логируем критические ошибки шифрования
        logger.critical(
            f"Encryption error {context.error_id}",
            extra={
                "error_id": context.error_id,
                "error_type": "encryption_error",
                "severity": "critical",
                "endpoint": context.endpoint,
                "method": context.method,
                "user_id": context.user_id,
                "ip_address": context.ip_address,
                "error_details": str(error),
                "traceback": traceback.format_exc()
            }
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": error_message,
                "error_id": context.error_id,
                "timestamp": context.timestamp.isoformat()
            }
        )
    
    def handle_rate_limit_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Обрабатывает ошибки rate limiting"""
        error_message = self._get_safe_error_message("rate_limit_error")
        
        # Логируем превышение лимитов
        logger.warning(
            f"Rate limit exceeded {context.error_id}",
            extra={
                "error_id": context.error_id,
                "error_type": "rate_limit_error",
                "severity": context.severity.value,
                "endpoint": context.endpoint,
                "method": context.method,
                "ip_address": context.ip_address,
                "user_agent": context.user_agent
            }
        )
        
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limit_error",
                "message": error_message,
                "error_id": context.error_id,
                "timestamp": context.timestamp.isoformat(),
                "retry_after": 60  # секунд
            }
        )
    
    def handle_generic_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Обрабатывает общие ошибки"""
        # Определяем тип ошибки
        error_type = self._classify_error(error)
        error_message = self._get_safe_error_message(error_type)
        
        # Логируем ошибку
        log_level = self._get_log_level(context.severity)
        logger.log(
            log_level,
            f"Error {context.error_id}",
            extra={
                "error_id": context.error_id,
                "error_type": error_type,
                "severity": context.severity.value,
                "endpoint": context.endpoint,
                "method": context.method,
                "user_id": context.user_id,
                "ip_address": context.ip_address,
                "error_details": str(error)[:self.max_error_message_length],
                "traceback": traceback.format_exc() if context.severity == ErrorSeverity.CRITICAL else None
            }
        )
        
        return JSONResponse(
            status_code=self._get_http_status_code(error_type),
            content={
                "error": error_type,
                "message": error_message,
                "error_id": context.error_id,
                "timestamp": context.timestamp.isoformat()
            }
        )
    
    def _get_safe_error_message(self, error_type: str) -> str:
        """Получает безопасное сообщение об ошибке"""
        return self.safe_errors.get(error_type, self.unsafe_errors.get(error_type, "Internal server error"))
    
    def _classify_error(self, error: Exception) -> str:
        """Классифицирует ошибку"""
        error_name = error.__class__.__name__.lower()
        
        if "validation" in error_name or "value" in error_name:
            return "validation_error"
        elif "authentication" in error_name or "unauthorized" in error_name:
            return "authentication_error"
        elif "authorization" in error_name or "forbidden" in error_name:
            return "authorization_error"
        elif "database" in error_name or "sql" in error_name:
            return "database_error"
        elif "encryption" in error_name or "crypto" in error_name:
            return "encryption_error"
        elif "timeout" in error_name:
            return "timeout_error"
        elif "rate" in error_name or "limit" in error_name:
            return "rate_limit_error"
        else:
            return "internal_error"
    
    def _get_http_status_code(self, error_type: str) -> int:
        """Получает HTTP статус код для типа ошибки"""
        status_codes = {
            "validation_error": 422,
            "authentication_error": 401,
            "authorization_error": 403,
            "not_found_error": 404,
            "rate_limit_error": 429,
            "timeout_error": 408,
            "internal_error": 500,
        }
        return status_codes.get(error_type, 500)
    
    def _get_log_level(self, severity: ErrorSeverity) -> int:
        """Получает уровень логирования для серьезности ошибки"""
        levels = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
        }
        return levels.get(severity, logging.ERROR)
    
    def _get_client_ip(self, request: Request) -> Optional[str]:
        """Получает IP адрес клиента"""
        # Проверяем заголовки прокси
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Используем IP из request
        if hasattr(request, "client") and request.client:
            return request.client.host
        
        return None

# Глобальный экземпляр
secure_error_handler = SecureErrorHandler()

# Удобные функции
def create_error_context(request: Request, severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> ErrorContext:
    """Создает контекст ошибки"""
    return secure_error_handler.create_error_context(request, severity)

def handle_validation_error(error: Exception, context: ErrorContext) -> JSONResponse:
    """Обрабатывает ошибки валидации"""
    return secure_error_handler.handle_validation_error(error, context)

def handle_authentication_error(error: Exception, context: ErrorContext) -> JSONResponse:
    """Обрабатывает ошибки аутентификации"""
    return secure_error_handler.handle_authentication_error(error, context)

def handle_authorization_error(error: Exception, context: ErrorContext) -> JSONResponse:
    """Обрабатывает ошибки авторизации"""
    return secure_error_handler.handle_authorization_error(error, context)

def handle_database_error(error: Exception, context: ErrorContext) -> JSONResponse:
    """Обрабатывает ошибки базы данных"""
    return secure_error_handler.handle_database_error(error, context)

def handle_encryption_error(error: Exception, context: ErrorContext) -> JSONResponse:
    """Обрабатывает ошибки шифрования"""
    return secure_error_handler.handle_encryption_error(error, context)

def handle_rate_limit_error(error: Exception, context: ErrorContext) -> JSONResponse:
    """Обрабатывает ошибки rate limiting"""
    return secure_error_handler.handle_rate_limit_error(error, context)

def handle_generic_error(error: Exception, context: ErrorContext) -> JSONResponse:
    """Обрабатывает общие ошибки"""
    return secure_error_handler.handle_generic_error(error, context)