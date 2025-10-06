"""
Request size limits middleware для защиты от DoS атак через большие payloads.

FIX: Добавлено для предотвращения memory exhaustion от больших запросов.
"""

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging

logger = logging.getLogger(__name__)

# Максимальный размер запроса по умолчанию: 10MB
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB

# Специфические лимиты для эндпоинтов
ENDPOINT_LIMITS = {
    "/v1/auth/register": 1 * 1024,        # 1 KB для регистрации
    "/v1/auth/login": 1 * 1024,           # 1 KB для логина
    "/v1/projects": 5 * 1024 * 1024,      # 5 MB для создания проектов
    "/v1/workspace": 20 * 1024 * 1024,    # 20 MB для загрузки файлов
}


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware для ограничения размера HTTP запросов.
    
    Защищает от:
    - DoS атак через большие payloads
    - Memory exhaustion
    - Bandwidth exhaustion
    """
    
    def __init__(self, app: ASGIApp, max_size: int = MAX_REQUEST_SIZE):
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next):
        """Process request and check size limit."""
        # Получаем Content-Length из заголовков
        content_length = request.headers.get("content-length")
        
        if content_length:
            try:
                content_length_int = int(content_length)
            except ValueError:
                logger.warning(f"Invalid Content-Length header: {content_length}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid Content-Length header"
                )
            
            # Определяем лимит для конкретного эндпоинта
            path = request.url.path
            limit = self._get_limit_for_path(path)
            
            # Проверяем размер
            if content_length_int > limit:
                logger.warning(
                    f"Request too large: {content_length_int} bytes "
                    f"(max {limit} bytes) for {path}"
                )
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail={
                        "error": "request_too_large",
                        "message": f"Request body too large (max {self._format_bytes(limit)})",
                        "max_size": limit,
                        "actual_size": content_length_int,
                    }
                )
        
        # Продолжаем обработку
        response = await call_next(request)
        return response
    
    def _get_limit_for_path(self, path: str) -> int:
        """
        Получить лимит для конкретного пути.
        
        Проверяет ENDPOINT_LIMITS и возвращает специфичный лимит или default.
        """
        # Проверяем точное совпадение
        if path in ENDPOINT_LIMITS:
            return ENDPOINT_LIMITS[path]
        
        # Проверяем префиксы (для /v1/workspace/... и т.д.)
        for endpoint_prefix, limit in ENDPOINT_LIMITS.items():
            if path.startswith(endpoint_prefix):
                return limit
        
        # Возвращаем дефолтный лимит
        return self.max_size
    
    @staticmethod
    def _format_bytes(size: int) -> str:
        """Форматировать размер в человекочитаемый вид."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
