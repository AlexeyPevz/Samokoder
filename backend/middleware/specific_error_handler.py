"""
Специфичные обработчики ошибок для разных типов исключений
Заменяет общие except Exception на специфичные обработчики
"""

import logging
import traceback
from typing import Union, Dict, Any
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
try:
    from sqlalchemy.exc import SQLAlchemyError
except ImportError:
    try:
        from sqlalchemy.exceptions import SQLAlchemyError
    except ImportError:
        # Fallback для случаев когда SQLAlchemy не установлен
        class SQLAlchemyError(Exception):
            pass
from redis.exceptions import RedisError
from httpx import HTTPError, TimeoutException, ConnectError
from pydantic import ValidationError
from tenacity import RetryError
import asyncio

from backend.core.exceptions import (
    SamokoderException, AuthenticationError, AuthorizationError,
    ValidationError as SamokoderValidationError, NotFoundError,
    ConflictError, RateLimitError, AIServiceError, DatabaseError,
    ExternalServiceError, ConfigurationError, ConnectionError, TimeoutError,
    EncryptionError, ProjectError, FileSystemError, NetworkError, CacheError,
    MonitoringError
)

logger = logging.getLogger(__name__)

class SpecificErrorHandler:
    """Специфичные обработчики ошибок"""
    
    @staticmethod
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Обработка ошибок валидации Pydantic"""
        errors = []
        for error in exc.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            message = error["msg"]
            errors.append(f"{field}: {message}")
        
        detail = "; ".join(errors)
        
        logger.warning(
            "validation_error",
            path=request.url.path,
            method=request.method,
            errors=errors,
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "detail": f"Ошибка валидации данных: {detail}",
                "error_code": "VALIDATION_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_http_exception(request: Request, exc: Union[HTTPException, StarletteHTTPException]) -> JSONResponse:
        """Обработка HTTP исключений"""
        logger.warning(
            "http_error",
            path=request.url.path,
            method=request.method,
            status_code=exc.status_code,
            detail=exc.detail,
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "detail": exc.detail,
                "error_code": f"HTTP_{exc.status_code}",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_samokoder_exception(request: Request, exc: SamokoderException) -> JSONResponse:
        """Обработка Samokoder исключений"""
        status_code = 500
        error_code = "SAMOKODER_ERROR"
        
        if isinstance(exc, AuthenticationError):
            status_code = 401
            error_code = "AUTHENTICATION_ERROR"
        elif isinstance(exc, AuthorizationError):
            status_code = 403
            error_code = "AUTHORIZATION_ERROR"
        elif isinstance(exc, SamokoderValidationError):
            status_code = 422
            error_code = "VALIDATION_ERROR"
        elif isinstance(exc, NotFoundError):
            status_code = 404
            error_code = "NOT_FOUND_ERROR"
        elif isinstance(exc, ConflictError):
            status_code = 409
            error_code = "CONFLICT_ERROR"
        elif isinstance(exc, RateLimitError):
            status_code = 429
            error_code = "RATE_LIMIT_ERROR"
        elif isinstance(exc, AIServiceError):
            status_code = 502
            error_code = "AI_SERVICE_ERROR"
        elif isinstance(exc, DatabaseError):
            status_code = 503
            error_code = "DATABASE_ERROR"
        elif isinstance(exc, ExternalServiceError):
            status_code = 502
            error_code = "EXTERNAL_SERVICE_ERROR"
        
        logger.error(
            "samokoder_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_code=error_code,
            detail=exc.message,
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=status_code,
            content={
                "error": "samokoder_error",
                "detail": exc.message,
                "error_code": error_code,
                "path": request.url.path,
                "details": exc.details
            }
        )
    
    @staticmethod
    async def handle_database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        """Обработка ошибок базы данных"""
        logger.error(
            "database_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=503,
            content={
                "error": "database_error",
                "detail": "Ошибка базы данных. Попробуйте позже.",
                "error_code": "DATABASE_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_redis_error(request: Request, exc: RedisError) -> JSONResponse:
        """Обработка ошибок Redis"""
        logger.error(
            "redis_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=503,
            content={
                "error": "redis_error",
                "detail": "Ошибка кэширования. Некоторые функции могут работать медленнее.",
                "error_code": "REDIS_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_http_client_error(request: Request, exc: HTTPError) -> JSONResponse:
        """Обработка ошибок HTTP клиентов"""
        status_code = 502
        error_code = "HTTP_CLIENT_ERROR"
        detail = "Ошибка внешнего сервиса"
        
        if isinstance(exc, TimeoutException):
            status_code = 504
            error_code = "TIMEOUT_ERROR"
            detail = "Внешний сервис не отвечает"
        elif isinstance(exc, ConnectError):
            status_code = 503
            error_code = "CONNECTION_ERROR"
            detail = "Не удается подключиться к внешнему сервису"
        
        logger.error(
            "http_client_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_code=error_code,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=status_code,
            content={
                "error": "http_client_error",
                "detail": detail,
                "error_code": error_code,
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_retry_error(request: Request, exc: RetryError) -> JSONResponse:
        """Обработка ошибок retry"""
        logger.error(
            "retry_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=503,
            content={
                "error": "retry_error",
                "detail": "Сервис временно недоступен. Попробуйте позже.",
                "error_code": "RETRY_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_asyncio_error(request: Request, exc: asyncio.TimeoutError) -> JSONResponse:
        """Обработка ошибок asyncio"""
        logger.error(
            "asyncio_timeout_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=504,
            content={
                "error": "timeout_error",
                "detail": "Операция превысила время ожидания",
                "error_code": "TIMEOUT_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_configuration_error(request: Request, exc: ConfigurationError) -> JSONResponse:
        """Обработка ошибок конфигурации"""
        logger.error(
            "configuration_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "configuration_error",
                "detail": "Configuration error. Contact administrator.",
                "error_code": "CONFIGURATION_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_encryption_error(request: Request, exc: EncryptionError) -> JSONResponse:
        """Обработка ошибок шифрования"""
        logger.error(
            "encryption_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "encryption_error",
                "detail": "Encryption/decryption failed",
                "error_code": "ENCRYPTION_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_project_error(request: Request, exc: ProjectError) -> JSONResponse:
        """Обработка ошибок проекта"""
        logger.error(
            "project_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "project_error",
                "detail": "Project operation failed",
                "error_code": "PROJECT_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_filesystem_error(request: Request, exc: FileSystemError) -> JSONResponse:
        """Обработка ошибок файловой системы"""
        logger.error(
            "filesystem_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "filesystem_error",
                "detail": "File system operation failed",
                "error_code": "FILESYSTEM_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_network_error(request: Request, exc: NetworkError) -> JSONResponse:
        """Обработка ошибок сети"""
        logger.error(
            "network_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=503,
            content={
                "error": "network_error",
                "detail": "Network operation failed",
                "error_code": "NETWORK_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_cache_error(request: Request, exc: CacheError) -> JSONResponse:
        """Обработка ошибок кэша"""
        logger.error(
            "cache_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=503,
            content={
                "error": "cache_error",
                "detail": "Cache operation failed",
                "error_code": "CACHE_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_monitoring_error(request: Request, exc: MonitoringError) -> JSONResponse:
        """Обработка ошибок мониторинга"""
        logger.error(
            "monitoring_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=503,
            content={
                "error": "monitoring_error",
                "detail": "Monitoring service unavailable",
                "error_code": "MONITORING_ERROR",
                "path": request.url.path
            }
        )
    
    @staticmethod
    async def handle_general_exception(request: Request, exc: Exception) -> JSONResponse:
        """Обработка общих исключений (последний резерв)"""
        error_id = f"ERR_{hash(str(exc)) % 1000000:06d}"
        
        logger.error(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            error_id=error_id,
            traceback=traceback.format_exc(),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "detail": "Внутренняя ошибка сервера. Обратитесь к администратору.",
                "error_code": "INTERNAL_ERROR",
                "error_id": error_id,
                "path": request.url.path
            }
        )

def setup_specific_error_handlers(app):
    """Настройка специфичных обработчиков ошибок"""
    handler = SpecificErrorHandler()
    
    # Регистрируем обработчики в порядке приоритета
    app.add_exception_handler(RequestValidationError, handler.handle_validation_error)
    app.add_exception_handler(HTTPException, handler.handle_http_exception)
    app.add_exception_handler(StarletteHTTPException, handler.handle_http_exception)
    app.add_exception_handler(SamokoderException, handler.handle_samokoder_exception)
    app.add_exception_handler(ConfigurationError, handler.handle_configuration_error)
    app.add_exception_handler(EncryptionError, handler.handle_encryption_error)
    app.add_exception_handler(ProjectError, handler.handle_project_error)
    app.add_exception_handler(FileSystemError, handler.handle_filesystem_error)
    app.add_exception_handler(NetworkError, handler.handle_network_error)
    app.add_exception_handler(CacheError, handler.handle_cache_error)
    app.add_exception_handler(MonitoringError, handler.handle_monitoring_error)
    app.add_exception_handler(SQLAlchemyError, handler.handle_database_error)
    app.add_exception_handler(RedisError, handler.handle_redis_error)
    app.add_exception_handler(HTTPError, handler.handle_http_client_error)
    app.add_exception_handler(RetryError, handler.handle_retry_error)
    app.add_exception_handler(asyncio.TimeoutError, handler.handle_asyncio_error)
    app.add_exception_handler(Exception, handler.handle_general_exception)
    
    logger.info("Specific error handlers configured")