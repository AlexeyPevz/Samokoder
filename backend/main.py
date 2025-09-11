from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import uuid
from datetime import datetime
from typing import Dict, Optional

from config.settings import settings
from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot
from backend.services.ai_service import get_ai_service
from backend.auth.dependencies import get_current_user
from backend.monitoring import monitoring, monitoring_middleware, get_metrics_response
from backend.models.requests import LoginRequest, ChatRequest
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

# Импортируем настроенный логгер из monitoring
from backend.monitoring import logger

# Создаем FastAPI приложение
app = FastAPI(
    title="Samokoder Backend API",
    description="AI-платформа для создания full-stack приложений",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


# Безопасная CORS конфигурация
# Строгие настройки CORS для безопасности
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

# Мониторинг middleware
app.middleware("http")(monitoring_middleware)

# Rate Limiting middleware
from backend.middleware.rate_limit_middleware import rate_limit_middleware
app.middleware("http")(rate_limit_middleware)

# Validation middleware
from backend.middleware.validation_middleware import validation_middleware
app.middleware("http")(validation_middleware)

# Error handlers
from backend.middleware.specific_error_handler import setup_specific_error_handlers
setup_specific_error_handlers(app)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Добавляет заголовки безопасности"""
    response = await call_next(request)
    
    # Заголовки безопасности
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return response

# CSRF protection middleware
@app.middleware("http")
async def csrf_protect(request: Request, call_next):
    """CSRF защита для изменяющих запросов"""
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

# Supabase клиент теперь управляется через connection_manager

# Инициализация Project State Manager при запуске
@app.on_event("startup")
async def startup_event():
    """Инициализация при запуске приложения"""
    try:
        await connection_manager.initialize()
        await project_state_manager.initialize()
        logger.info("All managers initialized")
    except ConfigurationError as e:
        logger.error("configuration_error_during_initialization", error=str(e), error_type=type(e).__name__)
        raise
    except ConnectionError as e:
        logger.error("connection_error_during_initialization", error=str(e), error_type=type(e).__name__)
        raise
    except Exception as e:
        logger.error("unexpected_error_during_initialization", error=str(e), error_type=type(e).__name__)
        raise ConfigurationError(f"Failed to initialize managers: {e}")

# === БАЗОВЫЕ ЭНДПОИНТЫ ===

@app.options("/{path:path}")
async def options_handler(path: str):
    """
    Обработчик для CORS preflight запросов.
    
    Args:
        path: Путь запроса
        
    Returns:
        Response: CORS заголовки для preflight запроса
    """
    from fastapi.responses import Response
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true"
        }
    )


@app.get("/")
async def root():
    """
    Корневой эндпоинт API.
    
    Returns:
        dict: Информация о API и его статусе
    """
    return {
        "message": "🚀 Samokoder Backend API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

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
        logger.error("monitoring_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=503, detail="Monitoring service unavailable")
    except Exception as e:
        logger.error("health_check_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Health check failed")

@app.get("/metrics")
async def metrics():
    """
    Prometheus метрики системы.
    
    Returns:
        Response: Метрики в формате Prometheus
    """
    return get_metrics_response()

@app.get("/health/detailed")
async def detailed_health_check():
    """Детальная проверка здоровья всех компонентов"""
    from backend.services.health_checker import health_checker
    
    health_status = monitoring.get_health_status()
    external_services = await health_checker.check_all_services()
    
    return {
        **health_status,
        "external_services": external_services,
        "active_projects": await project_state_manager.get_stats()["total_projects"],
        "memory_usage": {"used": 0, "total": 0, "percentage": 0},  # TODO: Получить реальное использование памяти
        "disk_usage": {"used": 0, "total": 0, "percentage": 0}  # TODO: Получить реальное использование диска
    }

# === АУТЕНТИФИКАЦИЯ ===

@app.post("/api/auth/login")
async def login(credentials: LoginRequest):
    """Вход через Supabase Auth (или mock для тестирования)"""
    try:
        # Pydantic автоматически валидирует данные и возвращает 422 при ошибке валидации
        email = credentials.email
        password = credentials.password
        
        # Если Supabase недоступен или URL содержит example, используем mock аутентификацию
        supabase_client = supabase_manager.get_client("anon")
        if not supabase_client or settings.supabase_url.endswith("example.supabase.co"):
            logger.warning("supabase_unavailable", fallback="mock_auth")
            return {
                "success": True,
                "message": "Успешный вход (mock режим)",
                "user": {
                    "id": f"mock_user_{email}",
                    "email": email,
                    "subscription_tier": "free",
                    "subscription_status": "active",
                    "api_credits_balance": 100.50,
                    "created_at": "2025-01-01T00:00:00Z",
                    "updated_at": "2025-01-01T00:00:00Z"
                },
                "access_token": f"mock_token_{email}",
                "token_type": "bearer",
                "expires_in": 3600
            }
        
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
                    "subscription_tier": "free",
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
        logger.error("authentication_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=401, detail="Authentication failed")
    except DatabaseError as e:
        logger.error("database_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=503, detail="Database unavailable")
    except Exception as e:
        logger.error("login_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=401, detail="Login failed")

@app.post("/api/auth/register")
async def register(user_data: dict):
    """Регистрация нового пользователя"""
    try:
        # Строгая проверка входных данных
        if not user_data:
            raise HTTPException(status_code=400, detail="Данные для регистрации обязательны")
        
        email = user_data.get("email")
        password = user_data.get("password")
        full_name = user_data.get("full_name")
        
        if not email or not password or not full_name:
            raise HTTPException(status_code=400, detail="Email, пароль и имя обязательны")
        
        if not isinstance(email, str) or not isinstance(password, str) or not isinstance(full_name, str):
            raise HTTPException(status_code=400, detail="Все поля должны быть строками")
        
        if not email.strip() or not password.strip() or not full_name.strip():
            raise HTTPException(status_code=400, detail="Поля не могут быть пустыми")
        
        # Если Supabase недоступен или URL содержит example, используем mock регистрацию
        supabase_client = supabase_manager.get_client("anon")
        if not supabase_client or settings.supabase_url.endswith("example.supabase.co"):
            logger.warning("supabase_unavailable", fallback="mock_register")
            return {
                "success": True,
                "message": "Пользователь успешно зарегистрирован (mock режим)",
                "user_id": f"mock_user_{email}",
                "email": email
            }
        
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
            return {
                "success": True,
                "message": "Пользователь успешно зарегистрирован",
                "user_id": response.user.id,
                "email": email
            }
        else:
            raise HTTPException(status_code=400, detail="Ошибка регистрации")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("register_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=400, detail=f"Ошибка регистрации: {str(e)}")

@app.post("/api/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Выход из системы"""
    try:
        supabase_client = supabase_manager.get_client("anon")
        if supabase_client:
            supabase_client.auth.sign_out()
        logger.info("user_logout_success", user_email=current_user.get('email'))
        return {"message": "Успешный выход"}
    except Exception as e:
        logger.error("logout_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=400, detail=f"Ошибка выхода: {str(e)}")

@app.get("/api/auth/user")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Получить информацию о текущем пользователе"""
    return {
        "user": current_user,
        "timestamp": datetime.now().isoformat()
    }

# === УПРАВЛЕНИЕ ПРОЕКТАМИ ===

# GET /api/projects - moved to projects router

# POST /api/projects - moved to projects router

# GET /api/projects/{project_id} - moved to projects router

# DELETE /api/projects/{project_id} - moved to projects router

# === ЧАТ И ГЕНЕРАЦИЯ ===
# All project endpoints moved to projects router

# @app.post("/api/projects/{project_id}/chat")
# async def chat_with_project(
    project_id: str,
    chat_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Отправить сообщение агентам проекта"""
    
    # Валидация входных данных
    if not chat_data.get("message"):
        raise HTTPException(status_code=400, detail="Сообщение обязательно")
    
    pilot_wrapper = await get_active_project(project_id, current_user["id"])
    if not pilot_wrapper:
        # Загружаем проект из базы если не в памяти
        await load_project_to_memory(project_id, current_user["id"])
        pilot_wrapper = await get_active_project(project_id, current_user["id"])
    
    if not pilot_wrapper:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    async def stream_response():
        try:
            async for update in pilot_wrapper.chat_with_agents(
                message=chat_data["message"],
                context=chat_data.get("context", "chat")
            ):
                yield f"data: {json.dumps(update)}\n\n"
        except Exception as e:
            logger.error("chat_stream_error", error=str(e), error_type=type(e).__name__)
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            # Очищаем ресурсы если нужно
            pass
    
    return StreamingResponse(
        stream_response(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )

# @app.post("/api/projects/{project_id}/generate")
# async def generate_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Запуск полной генерации проекта"""
    
    pilot_wrapper = await get_active_project(project_id, current_user["id"])
    if not pilot_wrapper:
        await load_project_to_memory(project_id, current_user["id"])
        pilot_wrapper = await get_active_project(project_id, current_user["id"])
    
    if not pilot_wrapper:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    # Обновляем статус в базе
    try:
        await execute_supabase_operation(
            lambda client: client.table("projects").update({
                "status": "generating",
                "updated_at": datetime.now().isoformat()
            }).eq("id", project_id).execute(),
            "anon"
        )
    except Exception as e:
        logger.error("update_project_status_error", error=str(e), error_type=type(e).__name__)
    
    async def stream_generation():
        try:
            async for update in pilot_wrapper.generate_full_app():
                yield f"data: {json.dumps(update)}\n\n"
                
            # Финальное обновление статуса
            await execute_supabase_operation(
                lambda client: client.table("projects").update({
                    "status": "completed",
                    "updated_at": datetime.now().isoformat()
                }).eq("id", project_id).execute(),
                "anon"
            )
            
        except Exception as e:
            logger.error("generation_stream_error", error=str(e), error_type=type(e).__name__)
            # Обновляем статус при ошибке
            try:
                await execute_supabase_operation(
                    lambda client: client.table("projects").update({
                        "status": "error",
                        "updated_at": datetime.now().isoformat()
                    }).eq("id", project_id).execute(),
                    "anon"
                )
            except Exception as update_error:
                logger.error("update_project_status_on_error", error=str(update_error), error_type=type(update_error).__name__)
            
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            # Очищаем ресурсы если нужно
            pass
    
    return StreamingResponse(
        stream_generation(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )

# === ФАЙЛЫ ПРОЕКТА ===

# @app.get("/api/projects/{project_id}/files")
# async def get_project_files(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получение структуры файлов проекта"""
    
    pilot_wrapper = await get_active_project(project_id, current_user["id"])
    if not pilot_wrapper:
        await load_project_to_memory(project_id, current_user["id"])
        pilot_wrapper = await get_active_project(project_id, current_user["id"])
    
    if not pilot_wrapper:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    try:
        file_tree = await pilot_wrapper.get_project_files()
        
        return {
            "project_id": project_id,
            "files": file_tree,
            "updated_at": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error("get_project_files_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка получения файлов: {str(e)}")

# @app.get("/api/projects/{project_id}/files/{file_path:path}")
# async def get_file_content(
    project_id: str,
    file_path: str, 
    current_user: dict = Depends(get_current_user)
):
    """Получение содержимого файла"""
    
    pilot_wrapper = await get_active_project(project_id, current_user["id"])
    if not pilot_wrapper:
        await load_project_to_memory(project_id, current_user["id"])
        pilot_wrapper = await get_active_project(project_id, current_user["id"])
    
    if not pilot_wrapper:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    try:
        content = pilot_wrapper.get_file_content(file_path)
        return {
            "file_path": file_path,
            "content": content,
            "size": len(content)
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except FileSystemError as e:
        logger.error("filesystem_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="File system error")
    except ProjectError as e:
        logger.error("project_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Project access error")
    except Exception as e:
        logger.error("get_file_content_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Failed to get file content")

# === ЭКСПОРТ ===

# @app.post("/api/projects/{project_id}/export")
# async def export_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Экспорт проекта в ZIP"""
    
    pilot_wrapper = await get_active_project(project_id, current_user["id"])
    if not pilot_wrapper:
        await load_project_to_memory(project_id, current_user["id"])
        pilot_wrapper = await get_active_project(project_id, current_user["id"])
    
    if not pilot_wrapper:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    try:
        zip_path = pilot_wrapper.create_zip_export()
        
        logger.info("project_exported", project_id=project_id)
        
        return FileResponse(
            zip_path,
            media_type="application/zip",
            filename=f"samokoder_project_{project_id}.zip"
        )
    except FileSystemError as e:
        logger.error("filesystem_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="File system error during export")
    except ProjectError as e:
        logger.error("project_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Project export error")
    except Exception as e:
        logger.error("export_project_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Export failed")

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

# === AI СЕРВИС ===

# @app.post("/api/ai/chat") - moved to ai router
# async def ai_chat(
    chat_request: ChatRequest,
    current_user: dict = Depends(get_current_user)
):
    """Чат с AI через централизованный сервис"""
    
    try:
        # Получаем API ключи пользователя
        user_api_keys = {}
        supabase_client = supabase_manager.get_client("anon")
        if supabase_client:
            from backend.services.encryption_service import get_encryption_service
            encryption_service = get_encryption_service()
            
            user_keys_response = await execute_supabase_operation(
                lambda client: client.table("user_api_keys").select("*").eq("user_id", current_user["id"]).eq("is_active", True).execute(),
                "anon"
            )
            if user_keys_response.data:
                # Расшифровываем API ключи
                for row in user_keys_response.data:
                    provider_name = row.get('provider_name', 'unknown')
                    try:
                        # Расшифровываем API ключ
                        decrypted_key = encryption_service.decrypt_api_key(
                            row['api_key_encrypted'], 
                            current_user["id"]
                        )
                        user_api_keys[provider_name] = decrypted_key
                    except Exception as e:
                        logger.warning("failed_to_decrypt_api_key", provider=provider_name, error=str(e))
                        continue
        else:
            # Mock режим - используем тестовые ключи
            user_api_keys = {
                "openrouter": "mock_openrouter_key",
                "openai": "mock_openai_key"
            }
        
        # Создаем AI сервис
        ai_service = get_ai_service(current_user["id"], user_api_keys)
        
        # Формируем сообщения
        messages = [
            {"role": "system", "content": "Ты - AI помощник для создания приложений. Отвечай кратко и по делу."},
            {"role": "user", "content": chat_request.message}
        ]
        
        # Выполняем запрос
        response = await ai_service.route_request(
            messages=messages,
            model=chat_request.model,
            provider=chat_request.provider.value if chat_request.provider else None,
            project_id="",  # ChatRequest не имеет project_id
            max_tokens=chat_request.max_tokens,
            temperature=chat_request.temperature
        )
        
        # Логируем AI запрос
        monitoring.log_ai_request(
            provider=response.provider.value,
            model=response.model,
            tokens=response.tokens_used,
            cost=response.cost_usd,
            success=response.success
        )
        
        if not response.success:
            raise HTTPException(status_code=500, detail=f"AI ошибка: {response.error}")
        
        return {
            "content": response.content,
            "provider": response.provider.value,
            "model": response.model,
            "usage": {
                "prompt_tokens": getattr(response, 'prompt_tokens', 0),
                "completion_tokens": getattr(response, 'completion_tokens', 0),
                "total_tokens": response.tokens_used,
                "prompt_cost": getattr(response, 'prompt_cost', 0.0),
                "completion_cost": getattr(response, 'completion_cost', 0.0),
                "total_cost": response.cost_usd
            },
            "response_time": response.response_time
        }
        
    except AIServiceError as e:
        logger.error("ai_service_error", error=str(e), error_type=type(e).__name__)
        monitoring.log_error(e, {"user_id": current_user["id"], "action": "ai_chat"})
        raise HTTPException(status_code=502, detail="AI service unavailable")
    except RateLimitError as e:
        logger.error("rate_limit_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    except Exception as e:
        logger.error("ai_chat_error", error=str(e), error_type=type(e).__name__)
        monitoring.log_error(e, {"user_id": current_user["id"], "action": "ai_chat"})
        raise HTTPException(status_code=500, detail="AI chat failed")

# @app.get("/api/ai/usage") - moved to ai router
# async def get_ai_usage(current_user: dict = Depends(get_current_user)):
    """Получение статистики использования AI"""
    
    try:
        # Получаем API ключи пользователя
        user_keys_response = await execute_supabase_operation(
            lambda client: client.table("user_api_keys").select("*").eq("user_id", current_user["id"]).eq("is_active", True).execute(),
            "anon"
        )
        user_api_keys = {
            row['provider']: row['api_key_decrypted'] 
            for row in user_keys_response.data
        } if user_keys_response.data else {}
        
        # Создаем AI сервис
        ai_service = get_ai_service(current_user["id"], user_api_keys)
        
        # Получаем статистику
        stats = await ai_service.get_usage_stats()
        
        return stats
        
    except Exception as e:
        logger.error("ai_usage_stats_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка получения статистики: {str(e)}")

# @app.get("/api/ai/providers") - moved to ai router
# async def get_ai_providers():
    """Получение списка доступных AI провайдеров"""
    
    return {
        "providers": [
            {
                "id": "openrouter",
                "name": "OpenRouter",
                "description": "Доступ к множеству AI моделей",
                "website": "https://openrouter.ai",
                "requires_key": True,
                "free_models": ["deepseek/deepseek-v3", "qwen/qwen-2.5-coder-32b"]
            },
            {
                "id": "openai",
                "name": "OpenAI",
                "description": "GPT-4o и GPT-4o-mini",
                "website": "https://openai.com",
                "requires_key": True,
                "free_models": []
            },
            {
                "id": "anthropic",
                "name": "Anthropic",
                "description": "Claude 3 Haiku и Sonnet",
                "website": "https://anthropic.com",
                "requires_key": True,
                "free_models": []
            },
            {
                "id": "groq",
                "name": "Groq",
                "description": "Быстрые Llama модели",
                "website": "https://groq.com",
                "requires_key": True,
                "free_models": ["llama-3-8b-8192", "llama-3-70b-8192"]
            }
        ]
    }

# @app.post("/api/ai/validate-keys") - moved to ai router
# async def validate_ai_keys(
    keys_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Проверка валидности API ключей"""
    
    try:
        # Создаем AI сервис с предоставленными ключами
        ai_service = get_ai_service(current_user["id"], keys_data)
        
        # Проверяем все ключи
        validation_results = await ai_service.validate_all_keys()
        
        return {
            "validation_results": validation_results,
            "valid_keys": [k for k, v in validation_results.items() if v],
            "invalid_keys": [k for k, v in validation_results.items() if not v]
        }
        
    except Exception as e:
        logger.error("ai_keys_validation_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка проверки ключей: {str(e)}")

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

async def load_project_to_memory(project_id: str, user_id: str):
    """Загружает проект в память из базы данных"""
    
    try:
        supabase_client = supabase_manager.get_client("anon")
        if not supabase_client:
            # Mock режим - создаем пустой проект
            user_api_keys = {
                "openrouter": "mock_openrouter_key",
                "openai": "mock_openai_key"
            }
            pilot_wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
            await add_active_project(project_id, user_id, pilot_wrapper)
            logger.info("project_loaded_to_memory_mock", project_id=project_id)
            return
        
        # Получаем данные проекта
        project_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).single().execute(),
            "anon"
        )
        
        if not project_response.data:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project_data = project_response.data
        
        # Получаем API ключи пользователя
        user_api_keys = {}
        user_keys_response = await execute_supabase_operation(
            lambda client: client.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute(),
            "anon"
        )
        if user_keys_response.data:
            # Здесь должна быть расшифровка ключей
            for row in user_keys_response.data:
                provider_name = row.get('provider_name', 'unknown')
                user_api_keys[provider_name] = f"encrypted_key_{row['id']}"
        
        # Создаем wrapper
        pilot_wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
        
        # Если проект уже создан, восстанавливаем его состояние
        if project_data['status'] != 'draft':
            await pilot_wrapper.restore_from_workspace()
        
        await add_active_project(project_id, user_id, pilot_wrapper)
        
        logger.info("project_loaded_to_memory", project_id=project_id)
        
    except Exception as e:
        logger.error("load_project_to_memory_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка загрузки проекта: {str(e)}")

# === MIDDLEWARE ДЛЯ ЛОГИРОВАНИЯ ===

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Middleware для логирования запросов"""
    start_time = datetime.now()
    
    response = await call_next(request)
    
    process_time = (datetime.now() - start_time).total_seconds()
    
    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        process_time=process_time
    )
    
    return response

# Graceful shutdown
@app.on_event("shutdown")
async def shutdown_event():
    """Обработка graceful shutdown"""
    try:
        from backend.services.health_checker import health_checker
        await health_checker.close()
        await project_state_manager.close()
        await connection_manager.close()
        logger.info("Application shutdown completed")
    except Exception as e:
        logger.error("error_during_shutdown", error=str(e), error_type=type(e).__name__)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )