"""
Улучшенный обработчик ошибок для FastAPI
Обеспечивает консистентную обработку ошибок и логирование
"""

import structlog
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Union
import traceback
import uuid
from datetime import datetime

logger = structlog.get_logger(__name__)

class ErrorResponse:
    """Стандартизированный формат ответа об ошибке"""
    
    def __init__(
        self,
        error: str,
        detail: str,
        error_code: str = None,
        error_id: str = None,
        timestamp: str = None,
        path: str = None,
        method: str = None
    ):
        self.error = error
        self.detail = detail
        self.error_code = error_code or "UNKNOWN_ERROR"
        self.error_id = error_id or str(uuid.uuid4())
        self.timestamp = timestamp or datetime.utcnow().isoformat()
        self.path = path
        self.method = method
    
    def to_dict(self) -> dict:
        """Преобразовать в словарь для JSON ответа"""
        return {
            "error": self.error,
            "detail": self.detail,
            "error_code": self.error_code,
            "error_id": self.error_id,
            "timestamp": self.timestamp,
            "path": self.path,
            "method": self.method
        }

def create_error_response(
    error: str,
    detail: str,
    status_code: int,
    error_code: str = None,
    request: Request = None
) -> JSONResponse:
    """
    Создать стандартизированный ответ об ошибке.
    
    Args:
        error: Тип ошибки
        detail: Детали ошибки
        status_code: HTTP статус код
        error_code: Внутренний код ошибки
        request: Объект запроса для контекста
        
    Returns:
        JSONResponse: Стандартизированный ответ об ошибке
    """
    error_response = ErrorResponse(
        error=error,
        detail=detail,
        error_code=error_code,
        path=request.url.path if request else None,
        method=request.method if request else None
    )
    
    # Логируем ошибку
    logger.error(
        "api_error",
        error=error,
        detail=detail,
        error_code=error_code,
        error_id=error_response.error_id,
        status_code=status_code,
        path=request.url.path if request else None,
        method=request.method if request else None
    )
    
    return JSONResponse(
        status_code=status_code,
        content=error_response.to_dict()
    )

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Обработчик ошибок валидации Pydantic"""
    errors = []
    for error in exc.errors():
        field = " -> ".join(str(loc) for loc in error["loc"])
        message = error["msg"]
        errors.append(f"{field}: {message}")
    
    detail = "; ".join(errors)
    
    return create_error_response(
        error="validation_error",
        detail=f"Ошибка валидации данных: {detail}",
        status_code=422,
        error_code="VALIDATION_ERROR",
        request=request
    )

async def http_exception_handler(request: Request, exc: Union[HTTPException, StarletteHTTPException]):
    """Обработчик HTTP исключений"""
    return create_error_response(
        error="http_error",
        detail=exc.detail,
        status_code=exc.status_code,
        error_code=f"HTTP_{exc.status_code}",
        request=request
    )

async def general_exception_handler(request: Request, exc: Exception):
    """Обработчик общих исключений"""
    error_id = str(uuid.uuid4())
    
    # Логируем полную информацию об ошибке
    logger.error(
        "unhandled_exception",
        error=str(exc),
        error_type=type(exc).__name__,
        error_id=error_id,
        traceback=traceback.format_exc(),
        path=request.url.path,
        method=request.method
    )
    
    return create_error_response(
        error="internal_server_error",
        detail="Внутренняя ошибка сервера. Обратитесь к администратору.",
        status_code=500,
        error_code="INTERNAL_ERROR",
        request=request
    )

def setup_error_handlers(app):
    """
    Настроить обработчики ошибок для FastAPI приложения.
    
    Args:
        app: FastAPI приложение
    """
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
    
    logger.info("error_handlers_configured", handlers=["validation", "http", "general"])