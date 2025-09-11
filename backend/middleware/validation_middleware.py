"""
Middleware для валидации входных данных
Проверяет размер запросов, типы данных и безопасность
"""

import json
import logging
from typing import Callable
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Максимальные размеры для разных типов запросов
MAX_REQUEST_SIZES = {
    "/api/auth/login": 1024,  # 1KB
    "/api/auth/register": 2048,  # 2KB
    "/api/projects": 10240,  # 10KB
    "/api/ai/chat": 51200,  # 50KB
    "/api/api-keys": 2048,  # 2KB
    "default": 10240  # 10KB по умолчанию
}

# Запрещенные паттерны в данных
FORBIDDEN_PATTERNS = [
    r"<script[^>]*>.*?</script>",  # XSS
    r"javascript:",  # JavaScript injection
    r"vbscript:",  # VBScript injection
    r"onload\s*=",  # Event handlers
    r"onerror\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"eval\s*\(",  # Code injection
    r"exec\s*\(",
    r"system\s*\(",
    r"shell_exec\s*\(",
    r"union\s+select",  # SQL injection
    r"drop\s+table",
    r"delete\s+from",
    r"insert\s+into",
    r"update\s+set",
    r"\.\./",  # Path traversal
    r"\.\.\\\\",
    r"\\\\\.\.",
    r"null\s*=",  # Null byte injection
    r"%00",
    r"\x00"
]

import re

async def validation_middleware(request: Request, call_next: Callable):
    """
    Middleware для валидации входных данных
    """
    try:
        # Проверяем размер запроса
        content_length = request.headers.get("content-length")
        if content_length:
            content_length = int(content_length)
            max_size = MAX_REQUEST_SIZES.get(request.url.path, MAX_REQUEST_SIZES["default"])
            
            if content_length > max_size:
                logger.warning(
                    f"Request too large: {content_length} bytes, max: {max_size} bytes",
                    extra={
                        "path": request.url.path,
                        "client_ip": request.client.host if request.client else "unknown"
                    }
                )
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "error": "Request too large",
                        "message": f"Максимальный размер запроса: {max_size} байт",
                        "received": content_length
                    }
                )
        
        # Проверяем Content-Type
        content_type = request.headers.get("content-type", "")
        if request.method in ["POST", "PUT", "PATCH"]:
            if not content_type.startswith("application/json"):
                logger.warning(
                    f"Invalid content type: {content_type}",
                    extra={
                        "path": request.url.path,
                        "method": request.method
                    }
                )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": "Invalid content type",
                        "message": "Ожидается application/json"
                    }
                )
        
        # Для POST/PUT/PATCH запросов проверяем тело
        if request.method in ["POST", "PUT", "PATCH"] and content_type.startswith("application/json"):
            # Читаем тело запроса
            body = await request.body()
            
            if body:
                try:
                    # Парсим JSON
                    json_data = json.loads(body.decode('utf-8'))
                    
                    # Проверяем на запрещенные паттерны
                    if await _check_forbidden_patterns(json_data, request.url.path):
                        logger.warning(
                            "Forbidden pattern detected in request body",
                            extra={
                                "path": request.url.path,
                                "client_ip": request.client.host if request.client else "unknown"
                            }
                        )
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={
                                "error": "Invalid data",
                                "message": "Обнаружены недопустимые данные в запросе"
                            }
                        )
                
                except json.JSONDecodeError as e:
                    logger.warning(
                        f"Invalid JSON in request: {e}",
                        extra={
                            "path": request.url.path,
                            "client_ip": request.client.host if request.client else "unknown"
                        }
                    )
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "Invalid JSON",
                            "message": "Некорректный JSON в запросе"
                        }
                    )
        
        # Проверяем заголовки на подозрительные значения
        if await _check_suspicious_headers(request):
            logger.warning(
                "Suspicious headers detected",
                extra={
                    "path": request.url.path,
                    "client_ip": request.client.host if request.client else "unknown"
                }
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "Invalid headers",
                    "message": "Обнаружены подозрительные заголовки"
                }
            )
        
        # Продолжаем обработку запроса
        response = await call_next(request)
        return response
        
    except Exception as e:
        logger.error(f"Validation middleware error: {e}")
        # В случае ошибки в middleware, пропускаем запрос
        return await call_next(request)

async def _check_forbidden_patterns(data: dict, path: str) -> bool:
    """
    Проверяет данные на наличие запрещенных паттернов
    """
    try:
        # Рекурсивно проверяем все строковые значения
        def check_value(value):
            if isinstance(value, str):
                # Проверяем каждый запрещенный паттерн
                for pattern in FORBIDDEN_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        logger.warning(f"Forbidden pattern found: {pattern} in value: {value[:100]}")
                        return True
            elif isinstance(value, dict):
                for v in value.values():
                    if check_value(v):
                        return True
            elif isinstance(value, list):
                for item in value:
                    if check_value(item):
                        return True
            return False
        
        return check_value(data)
        
    except Exception as e:
        logger.error(f"Error checking forbidden patterns: {e}")
        return False

async def _check_suspicious_headers(request: Request) -> bool:
    """
    Проверяет заголовки на подозрительные значения
    """
    try:
        suspicious_headers = [
            "user-agent",
            "referer",
            "x-forwarded-for",
            "x-real-ip"
        ]
        
        for header_name in suspicious_headers:
            header_value = request.headers.get(header_name, "")
            if header_value:
                # Проверяем на подозрительные паттерны в заголовках
                for pattern in FORBIDDEN_PATTERNS:
                    if re.search(pattern, header_value, re.IGNORECASE):
                        logger.warning(f"Suspicious header {header_name}: {header_value[:100]}")
                        return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking suspicious headers: {e}")
        return False