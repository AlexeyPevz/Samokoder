"""
Health check endpoints
"""
from fastapi import APIRouter, Depends
from backend.models.responses import HealthCheckResponse, DetailedHealthResponse, MetricsResponse
from backend.monitoring import get_metrics_response, check_external_services_health
from backend.services.connection_pool import connection_pool_manager
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Basic health check endpoint"""
    return HealthCheckResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
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
            services={
                "database": "healthy" if db_status else "unhealthy",
                "redis": "healthy" if redis_status else "unhealthy",
                "external_services": external_services
            }
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return DetailedHealthResponse(
            status="unhealthy",
            timestamp=datetime.now().isoformat(),
            version="1.0.0",
            services={"error": str(e)}
        )

@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics():
    """Get application metrics"""
    return await get_metrics_response()