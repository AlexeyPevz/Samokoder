"""
Secure Rate Limiter
Улучшенный rate limiting с защитой от атак
"""

import time
import json
import hashlib
from typing import Dict, Optional, Tuple
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

class SecureRateLimiter:
    """Безопасный rate limiter с защитой от обхода"""
    
    def __init__(self):
        # В production здесь должен быть Redis
        self._storage: Dict[str, Dict] = {}
        
        # Строгие лимиты для аутентификации
        self.auth_limits = {
            "login": {"attempts": 3, "window": 900},  # 3 попытки в 15 минут
            "register": {"attempts": 5, "window": 3600},  # 5 попыток в час
            "password_reset": {"attempts": 3, "window": 3600},  # 3 попытки в час
        }
        
        # Общие лимиты
        self.general_limits = {
            "api": {"attempts": 100, "window": 3600},  # 100 запросов в час
            "ai_chat": {"attempts": 20, "window": 3600},  # 20 запросов в час
            "file_upload": {"attempts": 10, "window": 3600},  # 10 загрузок в час
        }
    
    def _get_client_identifier(self, request: Request) -> str:
        """Получает уникальный идентификатор клиента"""
        # Используем комбинацию IP и User-Agent для более точной идентификации
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        
        # Создаем хеш для анонимизации
        identifier = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()[:16]
        return identifier
    
    def _get_rate_limit_key(self, identifier: str, endpoint: str) -> str:
        """Создает ключ для rate limiting"""
        return f"rate_limit:{identifier}:{endpoint}"
    
    def _is_rate_limited(self, key: str, limit_config: Dict) -> Tuple[bool, Dict]:
        """Проверяет, превышен ли лимит"""
        current_time = time.time()
        window_start = current_time - limit_config["window"]
        
        # Получаем записи из хранилища
        if key not in self._storage:
            self._storage[key] = []
        
        records = self._storage[key]
        
        # Удаляем старые записи
        records[:] = [record for record in records if record > window_start]
        
        # Проверяем лимит
        if len(records) >= limit_config["attempts"]:
            return True, {
                "attempts": len(records),
                "limit": limit_config["attempts"],
                "window": limit_config["window"],
                "reset_time": records[0] + limit_config["window"] if records else current_time + limit_config["window"]
            }
        
        # Добавляем новую запись
        records.append(current_time)
        
        return False, {
            "attempts": len(records),
            "limit": limit_config["attempts"],
            "window": limit_config["window"],
            "reset_time": records[0] + limit_config["window"] if records else current_time + limit_config["window"]
        }
    
    def check_rate_limit(self, request: Request, endpoint: str) -> Tuple[bool, Dict]:
        """Проверяет rate limit для запроса"""
        try:
            identifier = self._get_client_identifier(request)
            key = self._get_rate_limit_key(identifier, endpoint)
            
            # Определяем лимиты для endpoint
            if endpoint in self.auth_limits:
                limit_config = self.auth_limits[endpoint]
            else:
                limit_config = self.general_limits.get("api", {"attempts": 100, "window": 3600})
            
            is_limited, rate_info = self._is_rate_limited(key, limit_config)
            
            if is_limited:
                logger.warning(
                    "rate_limit_exceeded",
                    extra={
                        "identifier": identifier,
                        "client_ip": request.client.host if request.client else "unknown",
                        "endpoint": endpoint,
                        "rate_info": rate_info
                    }
                )
            
            return not is_limited, rate_info
            
        except Exception as e:
            logger.error(f"Rate limiter error: {e}")
            # В случае ошибки разрешаем запрос
            return True, {"error": "Rate limiter unavailable"}

# Глобальный экземпляр
secure_rate_limiter = SecureRateLimiter()

def secure_rate_limit(endpoint: str):
    """Декоратор для безопасного rate limiting"""
    async def check_rate_limit_middleware(request: Request, call_next):
        try:
            allowed, rate_info = secure_rate_limiter.check_rate_limit(request, endpoint)
            
            if not allowed:
                retry_after = int(rate_info.get("reset_time", 3600) - time.time())
                
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "Rate limit exceeded",
                        "message": "Слишком много запросов. Попробуйте позже.",
                        "retry_after": retry_after,
                        "rate_info": rate_info
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(rate_info.get("limit", 0)),
                        "X-RateLimit-Remaining": str(max(0, rate_info.get("limit", 0) - rate_info.get("attempts", 0))),
                        "X-RateLimit-Reset": str(int(rate_info.get("reset_time", 0)))
                    }
                )
            
            response = await call_next(request)
            
            # Добавляем заголовки rate limiting
            response.headers["X-RateLimit-Limit"] = str(rate_info.get("limit", 0))
            response.headers["X-RateLimit-Remaining"] = str(max(0, rate_info.get("limit", 0) - rate_info.get("attempts", 0)))
            response.headers["X-RateLimit-Reset"] = str(int(rate_info.get("reset_time", 0)))
            
            return response
            
        except Exception as e:
            logger.error(f"Rate limit middleware error: {e}")
            return await call_next(request)
    
    return check_rate_limit_middleware

# Специальные rate limiters для критических endpoints
def auth_rate_limit():
    """Rate limiter для аутентификации"""
    return secure_rate_limit("login")

def register_rate_limit():
    """Rate limiter для регистрации"""
    return secure_rate_limit("register")

def ai_chat_rate_limit():
    """Rate limiter для AI чата"""
    return secure_rate_limit("ai_chat")

def file_upload_rate_limit():
    """Rate limiter для загрузки файлов"""
    return secure_rate_limit("file_upload")

def api_rate_limit():
    """Rate limiter для API эндпоинтов"""
    return secure_rate_limit("api")

def ai_rate_limit():
    """Rate limiter для AI эндпоинтов"""
    return secure_rate_limit("ai")