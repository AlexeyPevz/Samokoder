"""
Health check endpoints
"""
from fastapi import APIRouter, Depends
from backend.models.responses import HealthCheckResponse, DetailedHealthResponse, MetricsResponse
from backend.monitoring import get_metrics_response, check_external_services_health
from backend.services.connection_pool import connection_pool_manager
import logging
from datetime import datetime
import time

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Basic health check endpoint"""
    return HealthCheckResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        version="1.0.0",
        uptime=time.time(),  # Время работы в секундах
        services={"api": "healthy", "database": "healthy", "redis": "healthy"}
    )

@router.get("/health/detailed", response_model=DetailedHealthResponse)
async def detailed_health_check():
    """Detailed health check with service status"""
    try:
        # Check database connection
        db_status = await connection_pool_manager.check_supabase_health()
        
        # Check Redis connection
        redis_status = await connection_pool_manager.check_redis_health()
        
        # Check external services
        external_services = await check_external_services_health()
        
        return DetailedHealthResponse(
            status="healthy" if all([db_status, redis_status]) else "degraded",
            timestamp=datetime.now().isoformat(),
            version="1.0.0",
            uptime=time.time(),
            services={
                "database": "healthy" if db_status else "unhealthy",
                "redis": "healthy" if redis_status else "unhealthy",
                "external_services": external_services
            },
            external_services=external_services,
            active_projects=0,  # TODO: Получить реальное количество проектов
            memory_usage={"used": 0, "total": 0, "percentage": 0},  # TODO: Получить реальное использование памяти
            disk_usage={"used": 0, "total": 0, "percentage": 0}  # TODO: Получить реальное использование диска
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return DetailedHealthResponse(
            status="unhealthy",
            timestamp=datetime.now().isoformat(),
            version="1.0.0",
            uptime=time.time(),
            services={"error": str(e)},
            external_services={},
            active_projects=0,
            memory_usage={"used": 0, "total": 0, "percentage": 0},
            disk_usage={"used": 0, "total": 0, "percentage": 0}
        )

@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics():
    """Get application metrics"""
    return await get_metrics_response()