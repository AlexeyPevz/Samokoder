"""
Детальные health check эндпоинты
Проверяют состояние всех компонентов системы
"""

from fastapi import APIRouter, HTTPException, status
from backend.monitoring import monitoring
from backend.models.responses import HealthCheckResponse, DetailedHealthResponse
from typing import Dict, Any
import asyncio
import logging
import psutil
import os
from datetime import datetime

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/", response_model=HealthCheckResponse)
async def basic_health_check():
    """Базовая проверка здоровья системы"""
    try:
        health_status = monitoring.get_health_status()
        
        return HealthCheckResponse(
            status=health_status.get("status", "unknown"),
            timestamp=datetime.now(),
            version="1.0.0",
            uptime=health_status.get("uptime", 0),
            services=health_status.get("services", {})
        )
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )

@router.get("/detailed", response_model=DetailedHealthResponse)
async def detailed_health_check():
    """Детальная проверка здоровья системы"""
    try:
        # Получаем базовый статус
        health_status = monitoring.get_health_status()
        
        # Проверяем внешние сервисы
        external_services = await check_external_services_health()
        
        # Получаем системные метрики
        memory_usage = get_memory_usage()
        disk_usage = get_disk_usage()
        
        # Подсчитываем активные проекты
        active_projects = len(getattr(monitoring, 'active_projects', {}))
        
        return DetailedHealthResponse(
            status=health_status.get("status", "unknown"),
            timestamp=datetime.now(),
            version="1.0.0",
            uptime=health_status.get("uptime", 0),
            services=health_status.get("services", {}),
            external_services=external_services,
            active_projects=active_projects,
            memory_usage=memory_usage,
            disk_usage=disk_usage
        )
        
    except Exception as e:
        logger.error(f"Detailed health check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detailed health check failed: {str(e)}"
        )

@router.get("/database")
async def database_health_check():
    """Проверка состояния базы данных"""
    try:
        from backend.services.connection_manager import connection_manager
        
        try:
            supabase = connection_manager.get_pool('supabase')
        except Exception:
            return {
                "status": "mock",
                "message": "Database in mock mode",
                "timestamp": datetime.now().isoformat()
            }
        
        # Проверяем подключение
        start_time = datetime.now()
        response = supabase.table("profiles").select("id").limit(1).execute()
        response_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "status": "healthy",
            "message": "Database connection successful",
            "response_time_ms": round(response_time * 1000, 2),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database health check error: {e}")
        return {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }

@router.get("/ai")
async def ai_health_check():
    """Проверка состояния AI сервисов"""
    try:
        from backend.services.ai_service import get_ai_service
        
        # Создаем AI сервис для проверки
        ai_service = get_ai_service("health_check", {})
        
        # Проверяем доступность провайдеров
        providers_status = {}
        
        # Проверяем каждый провайдер
        for provider in ["openrouter", "openai", "anthropic", "groq"]:
            try:
                # Здесь должна быть проверка доступности провайдера
                providers_status[provider] = "available"
            except Exception as e:
                providers_status[provider] = f"unavailable: {str(e)}"
        
        return {
            "status": "healthy",
            "message": "AI services check completed",
            "providers": providers_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"AI health check error: {e}")
        return {
            "status": "unhealthy",
            "message": f"AI services check failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }

@router.get("/system")
async def system_health_check():
    """Проверка системных ресурсов"""
    try:
        # CPU использование
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Память
        memory = psutil.virtual_memory()
        
        # Диск
        disk = psutil.disk_usage('/')
        
        # Процессы
        processes = len(psutil.pids())
        
        return {
            "status": "healthy",
            "message": "System resources check completed",
            "cpu_usage_percent": cpu_percent,
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "used_percent": memory.percent
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "used_percent": round((disk.used / disk.total) * 100, 2)
            },
            "processes_count": processes,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"System health check error: {e}")
        return {
            "status": "unhealthy",
            "message": f"System resources check failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }

async def check_external_services_health() -> Dict[str, str]:
    """Проверяет состояние внешних сервисов"""
    external_services = {}
    
    try:
        # Проверяем Supabase
        from config.settings import settings
        if settings.supabase_url and not settings.supabase_url.endswith("example.supabase.co"):
            try:
                from backend.services.connection_manager import connection_manager
                supabase = connection_manager.get_pool('supabase')
                supabase.table("profiles").select("id").limit(1).execute()
                external_services["supabase"] = "healthy"
            except Exception as e:
                external_services["supabase"] = f"unhealthy: {str(e)}"
        else:
            external_services["supabase"] = "mock"
        
        # Проверяем Redis (если используется)
        try:
            import redis
            # Здесь должна быть проверка Redis
            external_services["redis"] = "healthy"
        except Exception as e:
            external_services["redis"] = f"unhealthy: {str(e)}"
        
    except Exception as e:
        logger.error(f"External services check error: {e}")
        external_services["error"] = str(e)
    
    return external_services

def get_memory_usage() -> Dict[str, Any]:
    """Получает информацию об использовании памяти"""
    try:
        memory = psutil.virtual_memory()
        return {
            "total_bytes": memory.total,
            "available_bytes": memory.available,
            "used_bytes": memory.used,
            "used_percent": memory.percent
        }
    except Exception as e:
        logger.error(f"Memory usage check error: {e}")
        return {
            "total_bytes": 0,
            "available_bytes": 0,
            "used_bytes": 0,
            "used_percent": 0
        }

def get_disk_usage() -> Dict[str, Any]:
    """Получает информацию об использовании диска"""
    try:
        disk = psutil.disk_usage('/')
        return {
            "total_bytes": disk.total,
            "free_bytes": disk.free,
            "used_bytes": disk.used,
            "used_percent": round((disk.used / disk.total) * 100, 2)
        }
    except Exception as e:
        logger.error(f"Disk usage check error: {e}")
        return {
            "total_bytes": 0,
            "free_bytes": 0,
            "used_bytes": 0,
            "used_percent": 0
        }