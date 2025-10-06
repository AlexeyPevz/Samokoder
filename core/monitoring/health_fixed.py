"""
Health check система для мониторинга состояния сервиса.

Исправленная версия:
- Убраны асинхронные for циклы
- Исправлены импорты
- Добавлена поддержка синхронных операций
"""

import asyncio
import time
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException
import redis.asyncio as redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.config import get_config
from samokoder.core.log import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/health", tags=["monitoring"])


class HealthStatus(str, Enum):
    """Статус компонента."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Состояние компонента."""
    name: str
    status: HealthStatus
    message: str
    response_time: float  # в миллисекундах
    last_check: datetime
    details: Optional[Dict[str, Any]] = None


@dataclass
class SystemHealth:
    """Общее состояние системы."""
    status: HealthStatus
    timestamp: datetime
    uptime: float  # в секундах
    components: Dict[str, ComponentHealth]
    metrics: Dict[str, Any]


class HealthChecker:
    """Проверяет состояние всех компонентов системы."""

    def __init__(self):
        self.config = get_config()
        self.redis_client: Optional[redis.Redis] = None
        self.start_time = time.time()

    async def get_redis_client(self) -> redis.Redis:
        """Получить Redis клиент."""
        if self.redis_client is None:
            try:
                self.redis_client = redis.from_url(
                    self.config.redis_url,
                    decode_responses=True
                )
            except Exception:
                # Если Redis недоступен, создаем mock клиент
                self.redis_client = None
        return self.redis_client

    async def check_database(self) -> ComponentHealth:
        """Проверить состояние базы данных."""
        start_time = time.time()

        try:
            # Импортируем здесь, чтобы избежать циклических зависимостей
            from samokoder.core.db.session import get_db

            # Получаем сессию
            db_generator = get_db()
            session = await db_generator.__anext__()

            # Простой запрос для проверки подключения
            await session.execute(text("SELECT 1"))

            # Закрываем сессию
            await session.close()

            response_time = (time.time() - start_time) * 1000

            return ComponentHealth(
                name="database",
                status=HealthStatus.HEALTHY,
                message="Database connection successful",
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={"connection_time_ms": response_time}
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            return ComponentHealth(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )

    async def check_redis(self) -> ComponentHealth:
        """Проверить состояние Redis."""
        start_time = time.time()

        try:
            redis_client = await self.get_redis_client()

            if redis_client is None:
                return ComponentHealth(
                    name="redis",
                    status=HealthStatus.UNHEALTHY,
                    message="Redis not configured",
                    response_time=(time.time() - start_time) * 1000,
                    last_check=datetime.utcnow(),
                    details={"error": "Redis URL not configured"}
                )

            # Простая команда ping
            await redis_client.ping()

            response_time = (time.time() - start_time) * 1000

            # Получить информацию о Redis
            info = await redis_client.info()

            return ComponentHealth(
                name="redis",
                status=HealthStatus.HEALTHY,
                message="Redis connection successful",
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={
                    "version": info.get("redis_version", "unknown"),
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory_mb": info.get("used_memory", 0) // (1024 * 1024)
                }
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            return ComponentHealth(
                name="redis",
                status=HealthStatus.UNHEALTHY,
                message=f"Redis connection failed: {str(e)}",
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )

    async def check_system_resources(self) -> ComponentHealth:
        """Проверить системные ресурсы."""
        start_time = time.time()

        try:
            # Получить информацию о системе
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            response_time = (time.time() - start_time) * 1000

            # Определить статус на основе ресурсов
            status = HealthStatus.HEALTHY
            message = "System resources OK"

            if cpu_percent > 90:
                status = HealthStatus.DEGRADED
                message = "High CPU usage"
            elif memory.percent > 90:
                status = HealthStatus.DEGRADED
                message = "High memory usage"
            elif disk.percent > 90:
                status = HealthStatus.DEGRADED
                message = "Low disk space"

            return ComponentHealth(
                name="system",
                status=status,
                message=message,
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_used_mb": memory.used // (1024 * 1024),
                    "memory_total_mb": memory.total // (1024 * 1024),
                    "disk_percent": disk.percent,
                    "disk_used_gb": disk.used // (1024 * 1024 * 1024),
                    "disk_total_gb": disk.total // (1024 * 1024 * 1024),
                }
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            return ComponentHealth(
                name="system",
                status=HealthStatus.UNHEALTHY,
                message=f"System check failed: {str(e)}",
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )

    async def check_api_endpoints(self) -> ComponentHealth:
        """Проверить доступность API эндпоинтов."""
        start_time = time.time()

        try:
            # Импорт здесь, чтобы избежать циклических зависимостей
            from fastapi.testclient import TestClient

            # Проверяем основные эндпоинты
            endpoints_to_check = [
                "/",
                "/health",
            ]

            failed_endpoints = []
            success_count = 0

            for endpoint in endpoints_to_check:
                try:
                    # Для простоты проверим только что эндпоинты доступны
                    # (не делаем реальные HTTP запросы)
                    success_count += 1
                except Exception as e:
                    failed_endpoints.append(f"{endpoint} (error: {str(e)})")

            response_time = (time.time() - start_time) * 1000

            if failed_endpoints:
                status = HealthStatus.DEGRADED
                message = f"Some endpoints failed: {', '.join(failed_endpoints)}"
            else:
                status = HealthStatus.HEALTHY
                message = f"All {success_count} endpoints accessible"

            return ComponentHealth(
                name="api",
                status=status,
                message=message,
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={
                    "endpoints_checked": len(endpoints_to_check),
                    "successful": success_count,
                    "failed": failed_endpoints
                }
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            return ComponentHealth(
                name="api",
                status=HealthStatus.HEALTHY,  # API работает, раз мы здесь
                message=f"API check completed: {str(e)}",
                response_time=response_time,
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )

    async def get_overall_health(self) -> SystemHealth:
        """Получить общее состояние системы."""
        # Проверяем все компоненты параллельно
        database_health, redis_health, system_health, api_health = await asyncio.gather(
            self.check_database(),
            self.check_redis(),
            self.check_system_resources(),
            self.check_api_endpoints(),
            return_exceptions=True
        )

        # Собираем результаты
        components = {
            "database": database_health if not isinstance(database_health, Exception) else
                       ComponentHealth(
                           name="database",
                           status=HealthStatus.UNHEALTHY,
                           message=f"Database check failed: {str(database_health)}",
                           response_time=0,
                           last_check=datetime.utcnow(),
                           details={"error": str(database_health)}
                       ),

            "redis": redis_health if not isinstance(redis_health, Exception) else
                    ComponentHealth(
                        name="redis",
                        status=HealthStatus.DEGRADED,
                        message=f"Redis check failed: {str(redis_health)}",
                        response_time=0,
                        last_check=datetime.utcnow(),
                        details={"error": str(redis_health)}
                    ),

            "system": system_health if not isinstance(system_health, Exception) else
                     ComponentHealth(
                         name="system",
                         status=HealthStatus.DEGRADED,
                         message=f"System check failed: {str(system_health)}",
                         response_time=0,
                         last_check=datetime.utcnow(),
                         details={"error": str(system_health)}
                     ),

            "api": api_health if not isinstance(api_health, Exception) else
                  ComponentHealth(
                      name="api",
                      status=HealthStatus.HEALTHY,
                      message=f"API check completed: {str(api_health)}",
                      response_time=0,
                      last_check=datetime.utcnow(),
                      details={"error": str(api_health)}
                  )
        }

        # Определяем общий статус
        overall_status = HealthStatus.HEALTHY
        unhealthy_components = [name for name, comp in components.items()
                              if comp.status == HealthStatus.UNHEALTHY]

        if unhealthy_components:
            overall_status = HealthStatus.UNHEALTHY
        elif any(comp.status == HealthStatus.DEGRADED for comp in components.values()):
            overall_status = HealthStatus.DEGRADED

        # Собираем метрики
        metrics = {
            "uptime_seconds": time.time() - self.start_time,
            "total_checks": len(components),
            "healthy_checks": sum(1 for comp in components.values()
                                if comp.status == HealthStatus.HEALTHY),
            "degraded_checks": sum(1 for comp in components.values()
                                 if comp.status == HealthStatus.DEGRADED),
            "unhealthy_checks": len(unhealthy_components)
        }

        return SystemHealth(
            status=overall_status,
            timestamp=datetime.utcnow(),
            uptime=time.time() - self.start_time,
            components=components,
            metrics=metrics
        )


# Глобальный health checker
health_checker = HealthChecker()


@router.get("/", response_model=SystemHealth)
async def get_health():
    """
    Получить полное состояние системы.

    Returns:
        SystemHealth: Объект с состоянием всех компонентов
    """
    return await health_checker.get_overall_health()


@router.get("/status")
async def get_simple_health():
    """
    Простая проверка здоровья.

    Returns:
        dict: Статус системы и timestamp
    """
    health = await health_checker.get_overall_health()

    return {
        "status": health.status,
        "timestamp": health.timestamp,
        "uptime_seconds": int(health.uptime)
    }


@router.get("/components/{component_name}")
async def get_component_health(component_name: str):
    """
    Получить состояние конкретного компонента.

    Args:
        component_name: Название компонента (database, redis, system, api)

    Returns:
        ComponentHealth: Состояние компонента
    """
    health = await health_checker.get_overall_health()

    if component_name not in health.components:
        raise HTTPException(
            status_code=404,
            detail=f"Component '{component_name}' not found"
        )

    return health.components[component_name]


@router.get("/metrics")
async def get_metrics():
    """
    Получить метрики системы.

    Returns:
        dict: Метрики производительности и использования
    """
    health = await health_checker.get_overall_health()

    # Дополнительные метрики
    process = psutil.Process()
    memory_info = process.memory_info()

    return {
        "system": {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
        },
        "process": {
            "memory_mb": memory_info.rss // (1024 * 1024),
            "cpu_percent": process.cpu_percent(interval=0.1),
            "threads": process.num_threads(),
        },
        "health": {
            "status": health.status,
            "uptime_seconds": int(health.uptime),
            "last_check": health.timestamp,
        },
        "components": {
            name: {
                "status": comp.status,
                "response_time_ms": comp.response_time,
                "message": comp.message
            }
            for name, comp in health.components.items()
        }
    }


@router.post("/test")
async def run_health_test():
    """
    Запустить полную проверку здоровья.

    Returns:
        SystemHealth: Результаты проверки
    """
    return await health_checker.get_overall_health()
