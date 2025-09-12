"""
Главный API с использованием новой архитектуры
"""

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
from backend.adapters.adapter_factory import get_adapter_factory
from backend.core.dependency_injection import get_container
from backend.auth.dependencies import get_current_user
from backend.models.requests import LoginRequest, ChatRequest, RegisterRequest
from backend.models.responses import SubscriptionTier, RegisterResponse
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
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Получаем адаптеры
adapter_factory = get_adapter_factory()
ai_adapter = adapter_factory.get_ai_adapter()
monitoring_adapter = adapter_factory.get_monitoring_adapter()
security_adapter = adapter_factory.get_security_adapter()

# Настройка CORS
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:3001", 
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    settings.FRONTEND_URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Инициализация при запуске"""
    try:
        # Запускаем мониторинг
        await monitoring_adapter.start_monitoring()
        
        # Инициализируем DI контейнер
        container = get_container()
        
        print("✅ Samokoder Backend API v2.0.0 запущен")
        print("✅ Новая архитектура активирована")
        print("✅ DI контейнер инициализирован")
        print("✅ Адаптеры загружены")
        
    except Exception as e:
        print(f"❌ Ошибка при запуске: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Очистка при остановке"""
    try:
        await monitoring_adapter.stop_monitoring()
        print("✅ Samokoder Backend API остановлен")
    except Exception as e:
        print(f"❌ Ошибка при остановке: {e}")

# Health check endpoints
@app.get("/health")
async def health_check():
    """Проверка здоровья системы"""
    try:
        health_status = monitoring_adapter.get_system_health()
        return {
            "status": "healthy" if health_status["healthy"] else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "architecture": "new",
            "details": health_status
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/health/detailed")
async def detailed_health_check():
    """Детальная проверка здоровья"""
    try:
        # Получаем статус всех компонентов
        system_health = monitoring_adapter.get_system_health()
        ai_stats = ai_adapter.get_total_usage()
        security_status = security_adapter.get_user_security_status("system")
        
        return {
            "status": "healthy" if system_health["healthy"] else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "monitoring": system_health,
                "ai_service": ai_stats,
                "security": security_status
            },
            "architecture": {
                "di_container": "active",
                "adapters": "loaded",
                "interfaces": "implemented"
            }
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# AI endpoints
@app.post("/ai/chat")
async def chat_with_ai(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user)
):
    """Чат с AI используя новую архитектуру"""
    try:
        # Проверяем доступ пользователя
        access_check = security_adapter.check_user_access_with_mfa(
            user_id=current_user["id"],
            resource="ai",
            action="chat"
        )
        
        if not access_check["access_granted"]:
            raise AuthorizationError("Insufficient permissions for AI chat")
        
        # Генерируем ответ через AI адаптер
        response = await ai_adapter.generate_response(
            prompt=request.message,
            **request.dict(exclude={"message"})
        )
        
        return {
            "response": response,
            "user_id": current_user["id"],
            "timestamp": datetime.now().isoformat(),
            "architecture": "new"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ai/chat/stream")
async def chat_with_ai_stream(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user)
):
    """Потоковый чат с AI"""
    try:
        # Проверяем доступ пользователя
        access_check = security_adapter.check_user_access_with_mfa(
            user_id=current_user["id"],
            resource="ai",
            action="chat"
        )
        
        if not access_check["access_granted"]:
            raise AuthorizationError("Insufficient permissions for AI chat")
        
        async def generate_stream():
            async for chunk in ai_adapter.generate_stream(
                prompt=request.message,
                **request.dict(exclude={"message"})
            ):
                yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        
        return StreamingResponse(
            generate_stream(),
            media_type="text/plain",
            headers={"X-Architecture": "new"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Monitoring endpoints
@app.get("/monitoring/metrics")
async def get_metrics():
    """Получить метрики системы"""
    try:
        metrics = monitoring_adapter.get_system_health()
        return {
            "metrics": metrics,
            "timestamp": datetime.now().isoformat(),
            "architecture": "new"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/alerts")
async def get_alerts():
    """Получить алерты системы"""
    try:
        alert_adapter = adapter_factory.get_alert_adapter()
        alerts = alert_adapter.get_active_alerts()
        return {
            "alerts": alerts,
            "timestamp": datetime.now().isoformat(),
            "architecture": "new"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Security endpoints
@app.get("/security/user/{user_id}/permissions")
async def get_user_permissions(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить разрешения пользователя"""
    try:
        # Проверяем, что пользователь запрашивает свои разрешения или имеет права админа
        if current_user["id"] != user_id:
            admin_check = security_adapter.check_user_access_with_mfa(
                user_id=current_user["id"],
                resource="security",
                action="read"
            )
            if not admin_check["access_granted"]:
                raise AuthorizationError("Insufficient permissions")
        
        permissions = security_adapter.get_user_permissions(user_id)
        return {
            "user_id": user_id,
            "permissions": permissions,
            "timestamp": datetime.now().isoformat(),
            "architecture": "new"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/security/user/{user_id}/status")
async def get_user_security_status(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить статус безопасности пользователя"""
    try:
        # Проверяем права доступа
        if current_user["id"] != user_id:
            admin_check = security_adapter.check_user_access_with_mfa(
                user_id=current_user["id"],
                resource="security",
                action="read"
            )
            if not admin_check["access_granted"]:
                raise AuthorizationError("Insufficient permissions")
        
        status = security_adapter.get_user_security_status(user_id)
        return {
            "security_status": status,
            "timestamp": datetime.now().isoformat(),
            "architecture": "new"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Architecture info endpoint
@app.get("/architecture/info")
async def get_architecture_info():
    """Получить информацию об архитектуре"""
    try:
        container = get_container()
        registered_services = container.get_registered_services()
        available_adapters = adapter_factory.get_available_adapters()
        
        return {
            "architecture_version": "2.0.0",
            "di_container": {
                "active": True,
                "registered_services": registered_services
            },
            "adapters": {
                "available": available_adapters,
                "factory": "active"
            },
            "interfaces": {
                "monitoring": "implemented",
                "ai": "implemented", 
                "security": "implemented"
            },
            "patterns": {
                "dependency_injection": "active",
                "adapter_pattern": "active",
                "interface_segregation": "active",
                "single_responsibility": "active"
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))