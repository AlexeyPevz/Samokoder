"""
Тестовое приложение без проблемных middleware
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config.test_settings import test_settings

def create_test_app() -> FastAPI:
    """Создание тестового приложения без проблемных middleware"""
    
    app = FastAPI(
        title="Test API",
        description="Test application without problematic middleware",
        version="1.0.0",
        debug=test_settings.debug
    )
    
    # Добавляем только CORS middleware (безопасный)
    if not test_settings.disable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=test_settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    # Импортируем и добавляем роутеры
    from backend.api import api_keys, mfa, auth, health, projects, ai, file_upload, rbac
    
    # Добавляем роутеры
    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(api_keys.router, prefix="/api/api-keys", tags=["api-keys"])
    app.include_router(mfa.router, prefix="/api/auth/mfa", tags=["mfa"])
    app.include_router(projects.router, prefix="/api/projects", tags=["projects"])
    app.include_router(ai.router, prefix="/api/ai", tags=["ai"])
    app.include_router(file_upload.router, prefix="/api/upload", tags=["upload"])
    app.include_router(rbac.router, prefix="/api/rbac", tags=["rbac"])
    
    return app

# Создаем тестовое приложение
test_app = create_test_app()