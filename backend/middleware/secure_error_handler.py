"""
Secure Error Handler
Безопасная обработка ошибок без утечки информации
"""

import structlog
import traceback
import uuid
from datetime import datetime
from typing import Union, Dict, Any
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = structlog.get_logger(__name__)

class SecureErrorResponse:
    """Безопасный формат ответа об ошибке"""
    
    def __init__(
        self,
        error: str,
        detail: str,
        error_code: str = None,
        error_id: str = None,
        timestamp: str = None,
        path: str = None,
        method: str = None,
        show_details: bool = False
    ):
        self.error = error
        self.detail = detail
        self.error_code = error_code or "UNKNOWN_ERROR"
        self.error_id = error_id or str(uuid.uuid4())
        self.timestamp = timestamp or datetime.utcnow().isoformat()
        self.path = path
        self.method = method
        self.show_details = show_details
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь для JSON ответа"""
        response = {
            "error": self.error,
            "detail": self.detail,
            "error_code": self.error_code,
            "error_id": self.error_id,
            "timestamp": self.timestamp
        }
        
        # В production не показываем детали
        if self.show_details:
            response.update({
                "path": self.path,
                "method": self.method
            })
        
        return response

def create_secure_error_response(
    error: str,
    detail: str,
    status_code: int,
    error_code: str = None,
    request: Request = None,
    show_details: bool = False
) -> JSONResponse:
    """Создать безопасный ответ об ошибке"""
    
    # В production скрываем детали
    if not show_details:
        # Общие сообщения для пользователей
        if status_code == 500:
            detail = "Внутренняя ошибка сервера. Обратитесь к администратору."
        elif status_code == 404:
            detail = "Ресурс не найден."
        elif status_code == 403:
            detail = "Доступ запрещен."
        elif status_code == 401:
            detail = "Требуется аутентификация."
        elif status_code == 400:
            detail = "Некорректный запрос."
    
    error_response = SecureErrorResponse(
        error=error,
        detail=detail,
        error_code=error_code,
        path=request.url.path if request else None,
        method=request.method if request else None,
        show_details=show_details
    )
    
    # Логируем ошибку безопасно
    logger.error(
        "api_error",
        error=error,
        error_code=error_code,
        error_id=error_response.error_id,
        status_code=status_code,
        path=request.url.path if request else None,
        method=request.method if request else None,
        # НЕ логируем детали ошибки в production
        details=detail if show_details else "hidden"
    )
    
    return JSONResponse(
        status_code=status_code,
        content=error_response.to_dict()
    )

def sanitize_error_message(message: str) -> str:
    """Санитизирует сообщение об ошибке"""
    # Удаляем чувствительную информацию
    sensitive_patterns = [
        r'password["\']?\s*[:=]\s*["\'][^"\']*["\']',
        r'token["\']?\s*[:=]\s*["\'][^"\']*["\']',
        r'key["\']?\s*[:=]\s*["\'][^"\']*["\']',
        r'secret["\']?\s*[:=]\s*["\'][^"\']*["\']',
        r'file://[^\s]*',
        r'http://[^\s]*',
        r'https://[^\s]*',
    ]
    
    import re
    for pattern in sensitive_patterns:
        message = re.sub(pattern, '[REDACTED]', message, flags=re.IGNORECASE)
    
    return message

async def secure_validation_exception_handler(request: Request, exc: RequestValidationError):
    """Безопасный обработчик ошибок валидации"""
    errors = []
    for error in exc.errors():
        field = " -> ".join(str(loc) for loc in error["loc"])
        message = sanitize_error_message(error["msg"])
        errors.append(f"{field}: {message}")
    
    detail = "; ".join(errors)
    
    return create_secure_error_response(
        error="validation_error",
        detail=f"Ошибка валидации данных: {detail}",
        status_code=422,
        error_code="VALIDATION_ERROR",
        request=request
    )

async def secure_http_exception_handler(request: Request, exc: Union[HTTPException, StarletteHTTPException]):
    """Безопасный обработчик HTTP исключений"""
    # Санитизируем сообщение об ошибке
    sanitized_detail = sanitize_error_message(str(exc.detail))
    
    return create_secure_error_response(
        error="http_error",
        detail=sanitized_detail,
        status_code=exc.status_code,
        error_code=f"HTTP_{exc.status_code}",
        request=request
    )

async def secure_general_exception_handler(request: Request, exc: Exception):
    """Безопасный обработчик общих исключений"""
    error_id = str(uuid.uuid4())
    
    # Логируем полную информацию об ошибке (только для администраторов)
    logger.error(
        "unhandled_exception",
        error=str(exc),
        error_type=type(exc).__name__,
        error_id=error_id,
        traceback=traceback.format_exc(),
        path=request.url.path,
        method=request.method
    )
    
    # Определяем, показывать ли детали (только в development)
    show_details = request.app.debug if hasattr(request.app, 'debug') else False
    
    return create_secure_error_response(
        error="internal_server_error",
        detail="Внутренняя ошибка сервера. Обратитесь к администратору.",
        status_code=500,
        error_code="INTERNAL_ERROR",
        request=request,
        show_details=show_details
    )

def setup_secure_error_handlers(app):
    """Настроить безопасные обработчики ошибок"""
    app.add_exception_handler(RequestValidationError, secure_validation_exception_handler)
    app.add_exception_handler(HTTPException, secure_http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, secure_http_exception_handler)
    app.add_exception_handler(Exception, secure_general_exception_handler)
    
    logger.info("secure_error_handlers_configured", handlers=["validation", "http", "general"])

# Middleware для логирования запросов без чувствительных данных
@app.middleware("http")
async def secure_request_logging(request: Request, call_next):
    """Безопасное логирование запросов"""
    start_time = datetime.now()
    
    # Логируем начало запроса (без чувствительных данных)
    logger.info(
        "request_started",
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "")[:100]  # Ограничиваем длину
    )
    
    response = await call_next(request)
    
    process_time = (datetime.now() - start_time).total_seconds()
    
    # Логируем завершение запроса
    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        process_time=process_time
    )
    
    return response