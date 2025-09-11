from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import uuid
import time
import hmac
import hashlib
from datetime import datetime
from typing import Dict, Optional

from config.settings import settings
from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot
from backend.services.ai_service import get_ai_service
from backend.auth.dependencies import get_current_user
from backend.monitoring import monitoring, monitoring_middleware, get_metrics_response
from backend.models.requests import LoginRequest, ChatRequest, RegisterRequest
from backend.models.responses import SubscriptionTier, RegisterResponse
from backend.services.connection_manager import connection_manager
from backend.services.supabase_manager import supabase_manager, execute_supabase_operation
from backend.services.project_state_manager import project_state_manager, get_active_project, add_active_project, remove_active_project, is_project_active
from backend.core.exceptions import (
    SamokoderException, AuthenticationError, AuthorizationError, ValidationError,
    NotFoundError, ConflictError, RateLimitError, AIServiceError, DatabaseError,
    ExternalServiceError, ConfigurationError, ConnectionError, TimeoutError,
    EncryptionError, ProjectError, FileSystemError, NetworkError, CacheError,
    MonitoringError
)

# Создаем FastAPI приложение
app = FastAPI(
    title="Samokoder Backend API",
    description="AI-платформа для создания full-stack приложений",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Настройка CORS
allowed_origins = [
    "https://samokoder.com",
    "https://app.samokoder.com",
    "https://staging.samokoder.com"
]

# Добавляем локальные домены для разработки
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
    ],
    allow_credentials=True,
    max_age=3600,  # Кэширование preflight запросов
)

# Middleware для безопасности
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Добавляет заголовки безопасности"""
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

# CSRF защита
def validate_csrf_token(token: str) -> bool:
    """Безопасная валидация CSRF токена с HMAC"""
    try:
        if not token:
            return False
        
        # Получаем секретный ключ для CSRF
        csrf_secret = settings.secret_key
        if not csrf_secret:
            logger.error("CSRF secret key not configured")
            return False
        
        # Проверяем формат токена (должен содержать timestamp и HMAC)
        if '.' not in token:
            return False
        
        timestamp_str, hmac_signature = token.split('.', 1)
        
        # Проверяем timestamp (токен действителен 1 час)
        try:
            timestamp = int(timestamp_str)
            current_time = int(time.time())
            if current_time - timestamp > 3600:  # 1 час
                return False
        except ValueError:
            return False
        
        # Проверяем HMAC
        expected_signature = hmac.new(
            csrf_secret.encode(),
            timestamp_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(hmac_signature, expected_signature)
        
    except Exception as e:
        logger.warning(f"CSRF validation error: {e}")
        return False

@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """CSRF защита для не-GET запросов"""
    if request.method in ["GET", "HEAD", "OPTIONS"]:
        return await call_next(request)
    
    # CSRF защита включена для всех сред
    
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing"
        )
    
    if not validate_csrf_token(csrf_token):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token"
        )
    
    return await call_next(request)

# Инициализация менеджеров
async def initialize_managers():
    """Инициализация всех менеджеров"""
    try:
        await supabase_manager.initialize()
        await connection_manager.initialize()
        await project_state_manager.initialize()
        monitoring.initialize()
    except ConfigurationError as e:
        logger.error(f"configuration_error: {str(e)}")
        raise
    except ConnectionError as e:
        logger.error(f"connection_error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"initialization_error: {str(e)}")
        raise ConfigurationError(f"Failed to initialize managers: {e}")

# Логирование
import logging
logger = logging.getLogger(__name__)

def log_request_info(request: Request):
    """
    Логирует информацию о запросе
    
    Args:
        path: Путь запроса
        method: HTTP метод
        user_agent: User-Agent заголовок
        ip: IP адрес клиента
    """
    try:
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        logger.info("request_received", 
                   path=request.url.path,
                   method=request.method,
                   user_agent=user_agent,
                   ip=client_ip)
    except Exception as e:
        logger.error(f"log_request_error: {str(e)}")

# === HEALTH CHECKS ===

@app.get("/health", responses={500: {"description": "Internal server error"}})
async def health_check():
    """
    Проверка здоровья сервиса.
    
    Returns:
        dict: Статус здоровья всех компонентов системы
    """
    try:
        return monitoring.get_health_status()
    except MonitoringError as e:
        logger.error(f"monitoring_error: {str(e)}")
        raise HTTPException(status_code=503, detail="Monitoring service unavailable")
    except Exception as e:
        logger.error(f"health_check_error: {str(e)}")
        raise HTTPException(status_code=500, detail="Health check failed")

@app.get("/metrics")
async def metrics():
    """
    Prometheus метрики.
    
    Returns:
        str: Метрики в формате Prometheus
    """
    try:
        return get_metrics_response()
    except Exception as e:
        logger.error(f"metrics_error: {str(e)}")
        raise HTTPException(status_code=500, detail="Metrics unavailable")

# === АУТЕНТИФИКАЦИЯ ===

@app.post("/api/auth/login")
async def login(credentials: LoginRequest):
    """Вход через Supabase Auth (или mock для тестирования)"""
    try:
        # Pydantic автоматически валидирует данные и возвращает 422 при ошибке валидации
        email = credentials.email
        password = credentials.password
        
        # Проверяем доступность Supabase
        supabase_client = supabase_manager.get_client("anon")
        if not supabase_client:
            logger.error("Supabase client not available")
            raise HTTPException(
                status_code=503,
                detail="Authentication service unavailable"
            )
        
        if settings.supabase_url.endswith("example.supabase.co"):
            logger.error("Supabase URL not configured properly")
            raise HTTPException(
                status_code=503,
                detail="Database configuration error"
            )
        
        response = supabase_client.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        if response.user:
            logger.info("user_login_success", user_email=response.user.email)
            return {
                "success": True,
                "message": "Успешный вход",
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "full_name": getattr(response.user, 'user_metadata', {}).get('full_name', 'User'),
                    "avatar_url": getattr(response.user, 'user_metadata', {}).get('avatar_url'),
                    "subscription_tier": SubscriptionTier.FREE.value,
                    "subscription_status": "active",
                    "api_credits_balance": 100.50,
                    "created_at": response.user.created_at,
                    "updated_at": response.user.updated_at
                },
                "access_token": response.session.access_token,
                "token_type": "bearer",
                "expires_in": 3600
            }
        else:
            raise HTTPException(status_code=401, detail="Неверные учетные данные")
            
    except HTTPException:
        raise
    except AuthenticationError as e:
        logger.error(f"authentication_error: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed")
    except DatabaseError as e:
        logger.error(f"database_error: {str(e)}")
        raise HTTPException(status_code=503, detail="Database unavailable")
    except Exception as e:
        logger.error(f"login_error: {str(e)}")
        raise HTTPException(status_code=401, detail="Login failed")

@app.post("/api/auth/register", response_model=RegisterResponse, status_code=201)
async def register(user_data: RegisterRequest):
    """Регистрация нового пользователя"""
    try:
        # Pydantic автоматически валидирует данные
        email = user_data.email
        password = user_data.password
        full_name = user_data.full_name
        
        # Проверяем доступность Supabase
        supabase_client = supabase_manager.get_client("anon")
        if not supabase_client:
            logger.error("Supabase client not available")
            raise HTTPException(
                status_code=503,
                detail="Authentication service unavailable"
            )
        
        if settings.supabase_url.endswith("example.supabase.co"):
            logger.error("Supabase URL not configured properly")
            raise HTTPException(
                status_code=503,
                detail="Database configuration error"
            )
        
        # Реальная регистрация через Supabase
        response = supabase_client.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "full_name": full_name
                }
            }
        })
        
        if response.user:
            logger.info("user_register_success", user_email=email)
            return RegisterResponse(
                success=True,
                message="Пользователь успешно зарегистрирован",
                user_id=response.user.id,
                email=email
            )
        else:
            raise HTTPException(status_code=400, detail="Ошибка регистрации")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"register_error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Ошибка регистрации: {str(e)}")

@app.post("/api/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Выход из системы"""
    try:
        # В реальной реализации здесь была бы логика выхода из Supabase
        logger.info("user_logout", user_id=current_user["id"])
        return {
            "message": "Успешный выход из системы",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"logout_error: {str(e)}")
        raise HTTPException(status_code=500, detail="Logout failed")

@app.get("/api/auth/user")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Получить информацию о текущем пользователе"""
    try:
        return {
            "user": current_user,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"get_user_error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user info")

# === ПОДКЛЮЧЕНИЕ РОУТЕРОВ ===

# === MFA ===
from backend.api.mfa import router as mfa_router
app.include_router(mfa_router, prefix="/api/auth/mfa", tags=["MFA"])

# === RBAC ===
from backend.api.rbac import router as rbac_router
app.include_router(rbac_router, prefix="/api/rbac", tags=["RBAC"])

# === API КЛЮЧИ ===
from backend.api.api_keys import router as api_keys_router
app.include_router(api_keys_router, prefix="/api/api-keys", tags=["API Keys"])

# === PROJECTS ===
from backend.api.projects import router as projects_router
app.include_router(projects_router, prefix="/api/projects", tags=["Projects"])

# === AI ===
from backend.api.ai import router as ai_router
app.include_router(ai_router, prefix="/api/ai", tags=["AI"])

# === HEALTH CHECKS ===
from backend.api.health import router as health_router
app.include_router(health_router, prefix="/api/health", tags=["Health"])

# === STARTUP EVENT ===
@app.on_event("startup")
async def startup_event():
    """Инициализация при запуске"""
    try:
        await initialize_managers()
        logger.info("application_started", version="1.0.0")
    except Exception as e:
        logger.error(f"startup_error: {str(e)}")
        raise

# === SHUTDOWN EVENT ===
@app.on_event("shutdown")
async def shutdown_event():
    """Очистка при завершении"""
    try:
        await connection_manager.close()
        await project_state_manager.close()
        logger.info("application_shutdown")
    except Exception as e:
        logger.error(f"shutdown_error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)