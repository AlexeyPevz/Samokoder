from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
import json
import uuid
import os
from datetime import datetime
from typing import Dict, List, Optional

from config.settings import settings
from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot
from backend.services.ai_service import get_ai_service
from backend.auth.dependencies import get_current_user
from backend.monitoring import monitoring, monitoring_middleware, get_metrics_response
from backend.models.requests import LoginRequest

# Настройка структурированного логирования
import structlog

# Настройка structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Создаем FastAPI приложение
app = FastAPI(
    title="Samokoder Backend API",
    description="AI-платформа для создания full-stack приложений",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=True,
)

# Мониторинг middleware
app.middleware("http")(monitoring_middleware)

# Rate Limiting middleware
from backend.middleware.rate_limit_middleware import rate_limit_middleware
app.middleware("http")(rate_limit_middleware)

# Validation middleware
from backend.middleware.validation_middleware import validation_middleware
app.middleware("http")(validation_middleware)

# Supabase клиент (с проверкой URL)
supabase = None
try:
    # В тестовом режиме используем mock Supabase
    if os.getenv("ENVIRONMENT") == "test" or os.getenv("PYTEST_CURRENT_TEST"):
        logger.info("supabase_mock_mode", reason="test_environment")
        supabase = None  # Будем использовать mock режим в endpoints
    elif (settings.supabase_url and 
          settings.supabase_anon_key and 
          not settings.supabase_url.endswith("example.supabase.co") and
          not settings.supabase_anon_key.endswith("example") and
          "auhzhdndqyflfdfszapm" not in settings.supabase_url):  # Избегаем тестового URL
        supabase = create_client(
            settings.supabase_url, 
            settings.supabase_anon_key
        )
        logger.info("supabase_client_initialized", status="success")
    else:
        logger.warning("supabase_not_configured", reason="invalid_config")
        supabase = None
except Exception as e:
    logger.warning("supabase_client_failed", error=str(e), error_type=type(e).__name__)
    supabase = None

# Хранилище активных проектов (в продакшне использовать Redis)
active_projects: Dict[str, SamokoderGPTPilot] = {}

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
    except Exception as e:
        logger.error("health_check_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

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
    from backend.monitoring import check_external_services_health
    
    health_status = monitoring.get_health_status()
    external_services = await check_external_services_health()
    
    return {
        **health_status,
        "external_services": external_services,
        "active_projects": len(active_projects),
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
        if not supabase or settings.supabase_url.endswith("example.supabase.co"):
            logger.warning("supabase_unavailable", fallback="mock_auth")
            return {
                "message": "Успешный вход (mock режим)",
                "user": {
                    "id": f"mock_user_{email}",
                    "email": email,
                    "created_at": "2025-01-01T00:00:00Z"
                },
                "session": {
                    "access_token": f"mock_token_{email}",
                    "token_type": "bearer"
                }
            }
        
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        if response.user:
            logger.info("user_login_success", user_email=response.user.email)
            return {
                "message": "Успешный вход",
                "user": response.user,
                "session": response.session
            }
        else:
            raise HTTPException(status_code=401, detail="Неверные учетные данные")
            
    except Exception as e:
        logger.error("login_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=401, detail=f"Ошибка входа: {str(e)}")

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
        if not supabase or settings.supabase_url.endswith("example.supabase.co"):
            logger.warning("supabase_unavailable", fallback="mock_register")
            return {
                "message": "Пользователь успешно зарегистрирован (mock режим)",
                "user": {
                    "id": f"mock_user_{email}",
                    "email": email,
                    "full_name": full_name,
                    "created_at": "2025-01-01T00:00:00Z"
                },
                "access_token": f"mock_token_{email}",
                "token_type": "bearer"
            }
        
        # Реальная регистрация через Supabase
        response = supabase.auth.sign_up({
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
                "message": "Пользователь успешно зарегистрирован",
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "full_name": full_name,
                    "created_at": response.user.created_at
                },
                "access_token": response.session.access_token if response.session else None,
                "token_type": "bearer"
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
        supabase.auth.sign_out()
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

@app.get("/api/projects")
async def get_projects(current_user: dict = Depends(get_current_user)):
    """Получить список проектов пользователя"""
    try:
        # В тестовом режиме возвращаем mock данные
        if supabase is None:
            return {
                "projects": [],
                "total_count": 0
            }
        
        response = supabase.table("projects").select("*").eq("user_id", current_user["id"]).order("created_at", desc=True).execute()
        
        if not response.data:
            return {
                "projects": [],
                "total_count": 0
            }
        
        # Добавляем информацию о том, активен ли проект в памяти
        projects_with_status = []
        for project in response.data:
            project["is_active"] = project["id"] in active_projects
            projects_with_status.append(project)
        
        return {
            "projects": projects_with_status,
            "total_count": len(projects_with_status)
        }
    except Exception as e:
        logger.error("get_projects_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка получения проектов: {str(e)}")

@app.post("/api/projects")
async def create_project(
    project_data: dict,
    current_user: dict = Depends(get_current_user),
    background_tasks: BackgroundTasks = None
):
    """Создать новый проект"""
    
    # Валидация входных данных
    if not project_data or not isinstance(project_data, dict):
        raise HTTPException(status_code=400, detail="Невалидные данные проекта")
    
    if not project_data.get("name") or not project_data.get("description"):
        raise HTTPException(status_code=400, detail="Название и описание проекта обязательны")
    
    project_id = str(uuid.uuid4())
    user_id = current_user["id"]
    
    try:
        # Получаем API ключи пользователя
        user_api_keys = {}
        if supabase:
            from backend.services.encryption_service import get_encryption_service
            encryption_service = get_encryption_service()
            
            user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
            if user_keys_response.data:
                # Расшифровываем API ключи
                for row in user_keys_response.data:
                    provider_name = row.get('provider_name', 'unknown')
                    try:
                        # Расшифровываем API ключ
                        decrypted_key = encryption_service.decrypt_api_key(
                            row['api_key_encrypted'], 
                            user_id
                        )
                        user_api_keys[provider_name] = decrypted_key
                    except Exception as e:
                        logger.warning(f"Не удалось расшифровать API ключ для {provider_name}: {e}")
                        continue
        
        # Создаем обертку GPT-Pilot
        pilot_wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
        
        # Инициализируем проект
        init_result = await pilot_wrapper.initialize_project(
            app_description=project_data["description"],
            app_name=project_data["name"]
        )
        
        if init_result["status"] == "error":
            raise HTTPException(status_code=400, detail=init_result["message"])
        
        # Сохраняем в базу данных
        if supabase:
            project_record = {
                "id": project_id,
                "user_id": user_id,
                "name": project_data["name"],
                "description": project_data["description"], 
                "status": "draft",
                "ai_config": project_data.get("ai_config", {}),
                "tech_stack": project_data.get("tech_stack", {}),
                "workspace_path": init_result.get("workspace", f"workspaces/{user_id}/{project_id}"),
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            response = supabase.table("projects").insert(project_record).execute()
            
            if not response.data:
                raise HTTPException(status_code=500, detail="Ошибка сохранения проекта в базу данных")
        else:
            # Mock режим - только в памяти
            logger.warning("supabase_unavailable", fallback="memory_only")
        
        # Сохраняем активный проект
        active_projects[project_id] = pilot_wrapper
        
        logger.info("project_created", project_id=project_id, user_id=user_id)
        
        return {
            "project_id": project_id,
            "status": "draft",
            "message": "Проект создан, готов к работе",
            "workspace": init_result.get("workspace", f"workspaces/{user_id}/{project_id}")
        }
        
    except Exception as e:
        logger.error("create_project_error", error=str(e), error_type=type(e).__name__)
        # Очищаем активные проекты в случае ошибки
        if project_id in active_projects:
            del active_projects[project_id]
        raise HTTPException(status_code=500, detail=f"Ошибка создания проекта: {str(e)}")

@app.get("/api/projects/{project_id}")
async def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить детали проекта"""
    
    try:
        if supabase:
            response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"]).single().execute()
            
            if not response.data:
                raise HTTPException(status_code=404, detail="Проект не найден")
            
            project_data = response.data
            project_data["is_active"] = project_id in active_projects
            
            return {
                "project": project_data
            }
        else:
            # Mock режим - проверяем только активные проекты
            if project_id not in active_projects:
                raise HTTPException(status_code=404, detail="Проект не найден")
            
            pilot_wrapper = active_projects[project_id]
            return {
                "project": {
                    "id": project_id,
                    "user_id": current_user["id"],
                    "name": "Mock Project",
                    "description": "Mock project description",
                    "status": "active",
                    "created_at": "2025-01-01T00:00:00Z",
                    "is_active": True
                }
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_project_error", project_id=project_id, error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка получения проекта: {str(e)}")

@app.delete("/api/projects/{project_id}")
async def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Удалить проект"""
    
    try:
        if supabase:
            # Проверяем, что проект принадлежит пользователю
            project_response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"]).single().execute()
            
            if not project_response.data:
                raise HTTPException(status_code=404, detail="Проект не найден")
            
            # Удаляем из активных проектов
            if project_id in active_projects:
                del active_projects[project_id]
            
            # Удаляем из базы данных
            supabase.table("projects").delete().eq("id", project_id).execute()
            
            logger.info("project_deleted", project_id=project_id)
            
            return {"message": "Проект успешно удален"}
        else:
            # Mock режим - удаляем только из памяти
            if project_id not in active_projects:
                raise HTTPException(status_code=404, detail="Проект не найден")
            
            del active_projects[project_id]
            logger.info("project_deleted_mock", project_id=project_id)
            
            return {"message": "Проект успешно удален (mock режим)"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_project_error", project_id=project_id, error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка удаления проекта: {str(e)}")

# === ЧАТ И ГЕНЕРАЦИЯ ===

@app.post("/api/projects/{project_id}/chat")
async def chat_with_project(
    project_id: str,
    chat_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Отправить сообщение агентам проекта"""
    
    # Валидация входных данных
    if not chat_data.get("message"):
        raise HTTPException(status_code=400, detail="Сообщение обязательно")
    
    if project_id not in active_projects:
        # Загружаем проект из базы если не в памяти
        await load_project_to_memory(project_id, current_user["id"])
    
    if project_id not in active_projects:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    pilot_wrapper = active_projects[project_id]
    
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

@app.post("/api/projects/{project_id}/generate")
async def generate_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Запуск полной генерации проекта"""
    
    if project_id not in active_projects:
        await load_project_to_memory(project_id, current_user["id"])
    
    if project_id not in active_projects:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    pilot_wrapper = active_projects[project_id]
    
    # Обновляем статус в базе
    try:
        supabase.table("projects").update({
            "status": "generating",
            "updated_at": datetime.now().isoformat()
        }).eq("id", project_id).execute()
    except Exception as e:
        logger.error("update_project_status_error", error=str(e), error_type=type(e).__name__)
    
    async def stream_generation():
        try:
            async for update in pilot_wrapper.generate_full_app():
                yield f"data: {json.dumps(update)}\n\n"
                
            # Финальное обновление статуса
            supabase.table("projects").update({
                "status": "completed",
                "updated_at": datetime.now().isoformat()
            }).eq("id", project_id).execute()
            
        except Exception as e:
            logger.error("generation_stream_error", error=str(e), error_type=type(e).__name__)
            # Обновляем статус при ошибке
            try:
                supabase.table("projects").update({
                    "status": "error",
                    "updated_at": datetime.now().isoformat()
                }).eq("id", project_id).execute()
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

@app.get("/api/projects/{project_id}/files")
async def get_project_files(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получение структуры файлов проекта"""
    
    if project_id not in active_projects:
        await load_project_to_memory(project_id, current_user["id"])
    
    if project_id not in active_projects:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    pilot_wrapper = active_projects[project_id]
    
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

@app.get("/api/projects/{project_id}/files/{file_path:path}")
async def get_file_content(
    project_id: str,
    file_path: str, 
    current_user: dict = Depends(get_current_user)
):
    """Получение содержимого файла"""
    
    if project_id not in active_projects:
        await load_project_to_memory(project_id, current_user["id"])
    
    if project_id not in active_projects:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    pilot_wrapper = active_projects[project_id]
    
    try:
        content = pilot_wrapper.get_file_content(file_path)
        return {
            "file_path": file_path,
            "content": content,
            "size": len(content)
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Файл не найден")
    except Exception as e:
        logger.error("get_file_content_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка получения файла: {str(e)}")

# === ЭКСПОРТ ===

@app.post("/api/projects/{project_id}/export")
async def export_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Экспорт проекта в ZIP"""
    
    if project_id not in active_projects:
        await load_project_to_memory(project_id, current_user["id"])
    
    if project_id not in active_projects:
        raise HTTPException(status_code=404, detail="Проект не найден или не активен")
    
    pilot_wrapper = active_projects[project_id]
    
    try:
        zip_path = pilot_wrapper.create_zip_export()
        
        logger.info("project_exported", project_id=project_id)
        
        return FileResponse(
            zip_path,
            media_type="application/zip",
            filename=f"samokoder_project_{project_id}.zip"
        )
    except Exception as e:
        logger.error("export_project_error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail=f"Ошибка экспорта: {str(e)}")

# === MFA ===

from backend.api.mfa import router as mfa_router
app.include_router(mfa_router, prefix="/api/auth/mfa", tags=["MFA"])

# === RBAC ===

from backend.api.rbac import router as rbac_router
app.include_router(rbac_router, prefix="/api/rbac", tags=["RBAC"])

# === API КЛЮЧИ ===

from backend.api.api_keys import router as api_keys_router
app.include_router(api_keys_router, prefix="/api/api-keys", tags=["API Keys"])

# === HEALTH CHECKS ===

from backend.api.health import router as health_router
app.include_router(health_router, prefix="/api/health", tags=["Health"])

# === AI СЕРВИС ===

@app.post("/api/ai/chat")
async def ai_chat(
    chat_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Чат с AI через централизованный сервис"""
    
    if not chat_data.get("message"):
        raise HTTPException(status_code=400, detail="Сообщение обязательно")
    
    try:
        # Получаем API ключи пользователя
        user_api_keys = {}
        if supabase:
            from backend.services.encryption_service import get_encryption_service
            encryption_service = get_encryption_service()
            
            user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", current_user["id"]).eq("is_active", True).execute()
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
                        logger.warning(f"Не удалось расшифровать API ключ для {provider_name}: {e}")
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
            {"role": "user", "content": chat_data["message"]}
        ]
        
        # Выполняем запрос
        response = await ai_service.route_request(
            messages=messages,
            model=chat_data.get("model"),
            provider=chat_data.get("provider"),
            project_id=chat_data.get("project_id", ""),
            max_tokens=chat_data.get("max_tokens", 4096),
            temperature=chat_data.get("temperature", 0.7)
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
            "tokens_used": response.tokens_used,
            "cost_usd": response.cost_usd,
            "response_time": response.response_time
        }
        
    except Exception as e:
        logger.error("ai_chat_error", error=str(e), error_type=type(e).__name__)
        monitoring.log_error(e, {"user_id": current_user["id"], "action": "ai_chat"})
        raise HTTPException(status_code=500, detail=f"Ошибка AI чата: {str(e)}")

@app.get("/api/ai/usage")
async def get_ai_usage(current_user: dict = Depends(get_current_user)):
    """Получение статистики использования AI"""
    
    try:
        # Получаем API ключи пользователя
        user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", current_user["id"]).eq("is_active", True).execute()
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

@app.get("/api/ai/providers")
async def get_ai_providers():
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

@app.post("/api/ai/validate-keys")
async def validate_ai_keys(
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
        if not supabase:
            # Mock режим - создаем пустой проект
            user_api_keys = {
                "openrouter": "mock_openrouter_key",
                "openai": "mock_openai_key"
            }
            pilot_wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
            active_projects[project_id] = pilot_wrapper
            logger.info("project_loaded_to_memory_mock", project_id=project_id)
            return
        
        # Получаем данные проекта
        project_response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).single().execute()
        
        if not project_response.data:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project_data = project_response.data
        
        # Получаем API ключи пользователя
        user_api_keys = {}
        user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
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
        
        active_projects[project_id] = pilot_wrapper
        
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main_fixed:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )