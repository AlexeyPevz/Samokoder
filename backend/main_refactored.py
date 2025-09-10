"""
Рефакторированная версия main.py с модульной архитектурой
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
import logging
from datetime import datetime

# Импорты модулей
from backend.api import health, auth, projects, ai
from backend.middleware.rate_limit_middleware import RateLimitMiddleware
from backend.middleware.error_handler import custom_exception_handler
from backend.services.connection_pool import connection_pool_manager
from backend.monitoring import monitoring_middleware
from config.settings import settings

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app() -> FastAPI:
    """Создать и настроить FastAPI приложение"""
    
    app = FastAPI(
        title="Samokoder API",
        description="AI-powered code generation platform",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Monitoring middleware
    app.middleware("http")(monitoring_middleware)
    
    # Rate limiting middleware
    app.middleware("http")(RateLimitMiddleware(app))
    
    # Exception handlers
    app.exception_handler(RequestValidationError)(custom_exception_handler)
    app.exception_handler(ValidationError)(custom_exception_handler)
    
    # Include routers
    app.include_router(health.router, tags=["Health"])
    app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
    app.include_router(projects.router, prefix="/api/projects", tags=["Projects"])
    app.include_router(ai.router, prefix="/api/ai", tags=["AI"])
    
    # Startup and shutdown events
    @app.on_event("startup")
    async def startup_event():
        """Initialize services on startup"""
        logger.info("Starting Samokoder API...")
        await connection_pool_manager.initialize_all()
        logger.info("Samokoder API started successfully")
    
    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown"""
        logger.info("Shutting down Samokoder API...")
        await connection_pool_manager.close_all()
        logger.info("Samokoder API shutdown complete")
    
    return app

# Создаем приложение
app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main_refactored:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )