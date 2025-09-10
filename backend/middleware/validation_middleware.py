"""
Middleware для валидации и санитизации запросов
Обеспечивает безопасную обработку входящих данных
"""

import json
import structlog
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Callable
from backend.validators.input_validator import validator

logger = structlog.get_logger(__name__)

class ValidationMiddleware:
    """Middleware для валидации входящих запросов"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Валидация размера запроса
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                is_valid, error = validator.validate_request_size(size)
                if not is_valid:
                    logger.warning(
                        "request_size_exceeded",
                        size=size,
                        path=request.url.path,
                        method=request.method
                    )
                    response = JSONResponse(
                        status_code=413,
                        content={
                            "error": "request_too_large",
                            "detail": error
                        }
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                logger.warning(
                    "invalid_content_length",
                    content_length=content_length,
                    path=request.url.path
                )
        
        # Валидация Content-Type
        content_type = request.headers.get("content-type", "")
        if request.method in ["POST", "PUT", "PATCH"]:
            if not content_type.startswith("application/json"):
                logger.warning(
                    "invalid_content_type",
                    content_type=content_type,
                    path=request.url.path,
                    method=request.method
                )
                response = JSONResponse(
                    status_code=415,
                    content={
                        "error": "unsupported_media_type",
                        "detail": "Требуется Content-Type: application/json"
                    }
                )
                await response(scope, receive, send)
                return
        
        # Валидация JSON данных
        if content_type.startswith("application/json"):
            try:
                # Читаем тело запроса
                body = await request.body()
                if body:
                    try:
                        json_data = json.loads(body)
                        
                        # Валидация на подозрительное содержимое
                        is_valid, errors = validator.validate_json_data(json_data)
                        if not is_valid:
                            logger.warning(
                                "suspicious_content_detected",
                                errors=errors,
                                path=request.url.path,
                                method=request.method
                            )
                            response = JSONResponse(
                                status_code=400,
                                content={
                                    "error": "invalid_content",
                                    "detail": "Обнаружено подозрительное содержимое",
                                    "errors": errors
                                }
                            )
                            await response(scope, receive, send)
                            return
                    except json.JSONDecodeError as e:
                        logger.warning(
                            "invalid_json",
                            error=str(e),
                            path=request.url.path,
                            method=request.method
                        )
                        response = JSONResponse(
                            status_code=400,
                            content={
                                "error": "invalid_json",
                                "detail": "Невалидный JSON"
                            }
                        )
                        await response(scope, receive, send)
                        return
            except Exception as e:
                logger.error(
                    "validation_middleware_error",
                    error=str(e),
                    error_type=type(e).__name__,
                    path=request.url.path,
                    method=request.method
                )
                response = JSONResponse(
                    status_code=500,
                    content={
                        "error": "validation_error",
                        "detail": "Ошибка валидации запроса"
                    }
                )
                await response(scope, receive, send)
                return
        
        # Валидация параметров URL
        if request.query_params:
            for key, value in request.query_params.items():
                # Проверка на подозрительные символы в параметрах
                if any(char in value for char in ['<', '>', '"', "'", '&', '\x00']):
                    logger.warning(
                        "suspicious_query_param",
                        key=key,
                        value=value,
                        path=request.url.path,
                        method=request.method
                    )
                    response = JSONResponse(
                        status_code=400,
                        content={
                            "error": "invalid_query_param",
                            "detail": f"Параметр '{key}' содержит недопустимые символы"
                        }
                    )
                    await response(scope, receive, send)
                    return
        
        # Валидация заголовков
        suspicious_headers = []
        for header_name, header_value in request.headers.items():
            if any(char in header_value for char in ['\x00', '\r', '\n']):
                suspicious_headers.append(header_name)
        
        if suspicious_headers:
            logger.warning(
                "suspicious_headers",
                headers=suspicious_headers,
                path=request.url.path,
                method=request.method
            )
            response = JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_headers",
                    "detail": "Заголовки содержат недопустимые символы"
                }
            )
            await response(scope, receive, send)
            return
        
        # Логирование успешной валидации
        logger.debug(
            "request_validated",
            path=request.url.path,
            method=request.method,
            content_length=content_length,
            content_type=content_type
        )
        
        await self.app(scope, receive, send)

def create_validation_middleware(app):
    """
    Создать middleware для валидации.
    
    Args:
        app: FastAPI приложение
        
    Returns:
        ValidationMiddleware: Настроенный middleware
    """
    return ValidationMiddleware(app)