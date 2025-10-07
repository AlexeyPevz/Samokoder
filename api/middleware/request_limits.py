"""
Request size limits middleware для защиты от DoS атак через большие payloads.

Улучшено: ограничение применяется даже при отсутствии заголовка Content-Length,
с подсчётом полученных байт по мере чтения тела запроса.
"""

from fastapi import status
from starlette.types import ASGIApp, Receive, Scope, Send
import logging
import json

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


class RequestSizeLimitMiddleware:
    """
    ASGI middleware для ограничения размера HTTP запросов.

    - Если есть Content-Length, проверяем до передачи в приложение
    - Если нет Content-Length, оборачиваем receive и считаем байты потока
    """

    def __init__(self, app: ASGIApp, max_size: int = MAX_REQUEST_SIZE):
        self.app = app
        self.max_size = max_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        limit = self._get_limit_for_path(path)

        # Pre-check Content-Length if provided
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        content_length = headers.get("content-length")
        if content_length:
            try:
                cl_int = int(content_length)
            except ValueError:
                await self._send_error(send, status.HTTP_400_BAD_REQUEST, {
                    "error": "invalid_content_length",
                    "message": "Invalid Content-Length header",
                })
                return
            if cl_int > limit:
                logger.warning(f"Request too large by Content-Length: {cl_int} > {limit} for {path}")
                await self._send_error(send, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, {
                    "error": "request_too_large",
                    "message": f"Request body too large (max {self._format_bytes(limit)})",
                    "max_size": limit,
                    "actual_size": cl_int,
                })
                return

        total = 0

        async def limited_receive() -> dict:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"") or b""
                total += len(body)
                if total > limit:
                    logger.warning(f"Request too large while streaming: {total} > {limit} for {path}")
                    # Отправляем 413 и прекращаем обработку
                    await self._send_error(send, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, {
                        "error": "request_too_large",
                        "message": f"Request body too large (max {self._format_bytes(limit)})",
                        "max_size": limit,
                        "actual_size": total,
                    })
                    # После отправки ответа дальнейшая цепочка не должна продолжаться
                    return {"type": "http.disconnect"}
            return message

        await self.app(scope, limited_receive, send)

    async def _send_error(self, send: Send, status_code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        await send({"type": "http.response.start", "status": status_code, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    def _get_limit_for_path(self, path: str) -> int:
        # Проверяем точное совпадение
        if path in ENDPOINT_LIMITS:
            return ENDPOINT_LIMITS[path]
        # Проверяем префиксы
        for endpoint_prefix, limit in ENDPOINT_LIMITS.items():
            if path.startswith(endpoint_prefix):
                return limit
        return self.max_size

    @staticmethod
    def _format_bytes(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
