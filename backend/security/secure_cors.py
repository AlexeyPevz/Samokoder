"""
Secure CORS Configuration
Исправления безопасности на основе ASVS аудита
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config.settings import settings

def setup_secure_cors(app: FastAPI):
    """Настройка безопасного CORS"""
    
    # Строгие настройки CORS
    allowed_origins = [
        "https://samokoder.com",
        "https://app.samokoder.com",
        "https://staging.samokoder.com"
    ]
    
    # В development добавляем localhost
    if settings.environment == "development":
        allowed_origins.extend([
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173"
        ])
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,  # Только доверенные домены
        allow_methods=["GET", "POST", "PUT", "DELETE"],  # Убираем OPTIONS
        allow_headers=[
            "Authorization",
            "Content-Type", 
            "X-CSRF-Token",
            "X-Requested-With"
        ],  # Ограниченный список заголовков
        allow_credentials=True,
        max_age=3600,  # Кэширование preflight запросов
    )

def setup_security_headers(app: FastAPI):
    """Добавляет заголовки безопасности"""
    
    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        
        # Заголовки безопасности
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # X-XSS-Protection устарел, используем CSP
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Более гибкий CSP для API
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.openai.com https://api.anthropic.com https://openrouter.ai; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "speaker=()"
        )
        
        return response

def setup_csrf_protection(app: FastAPI):
    """Настройка CSRF защиты"""
    
    @app.middleware("http")
    async def csrf_protect(request, call_next):
        # Пропускаем GET запросы и preflight
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)
        
        # Проверяем CSRF токен для изменяющих запросов
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={"error": "CSRF token missing"}
            )
        
        # Валидируем CSRF токен (здесь должна быть реальная валидация)
        if not validate_csrf_token(csrf_token):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid CSRF token"}
            )
        
        return await call_next(request)

def validate_csrf_token(token: str) -> bool:
    """Валидация CSRF токена"""
    # Здесь должна быть реальная валидация токена
    # Для демонстрации возвращаем True
    return len(token) > 10
