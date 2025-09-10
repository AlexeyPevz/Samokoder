"""
Улучшенная версия main.py с Pydantic валидацией и исправленными проблемами безопасности
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, status
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from supabase import create_client, Client
import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
from pathlib import Path

# Импорты моделей валидации
from backend.models.requests import (
    LoginRequest, RegisterRequest, ProjectCreateRequest, ProjectUpdateRequest,
    ProjectListRequest, ChatRequest, AIUsageRequest, APIKeyCreateRequest,
    APIKeyUpdateRequest, UserSettingsUpdateRequest, FileUploadRequest,
    FileContentRequest, ExportRequest, SearchRequest, APIKeyValidationRequest
)
from backend.models.responses import (
    BaseResponse, ErrorResponse, LoginResponse, ProjectResponse, ProjectListResponse,
    ProjectCreateResponse, AIResponse, AIUsageStatsResponse, APIKeyResponse,
    APIKeyListResponse, APIKeyValidationResponse, UserSettingsResponse,
    FileInfoResponse, FileTreeResponse, ExportResponse, AIProvidersResponse,
    HealthCheckResponse, DetailedHealthResponse, MetricsResponse
)

from config.settings import settings
from backend.services.gpt_pilot_integration import GPTPilotIntegration
from backend.services.ai_service import get_ai_service
from backend.auth.dependencies import get_current_user
from backend.monitoring import monitoring, monitoring_middleware, get_metrics_response
from backend.middleware.rate_limit_middleware import (
    RateLimitMiddleware, auth_rate_limit, api_rate_limit, ai_rate_limit
)
from backend.services.connection_pool import connection_pool_manager

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Создаем FastAPI приложение
app = FastAPI(
    title="Samokoder Backend API",
    description="AI-платформа для создания full-stack приложений",
    version="1.0.0",
    docs_url="/docs" if settings.enable_api_docs else None,
    redoc_url="/redoc" if settings.enable_api_docs else None
)

# CORS middleware с улучшенной безопасностью
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    allow_credentials=True,
    max_age=3600,
)

# Мониторинг middleware
app.middleware("http")(monitoring_middleware)

# Rate limiting middleware
app.middleware("http")(RateLimitMiddleware(app))

# Инициализация пулов соединений при старте
@app.on_event("startup")
async def startup_event():
    """Инициализация при запуске приложения"""
    try:
        await connection_pool_manager.initialize_all()
        logger.info("Application startup completed successfully")
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Очистка при остановке приложения"""
    try:
        await connection_pool_manager.close_all()
        logger.info("Application shutdown completed successfully")
    except Exception as e:
        logger.error(f"Application shutdown error: {e}")

# Supabase клиент (с проверкой URL)
supabase = None
try:
    if (settings.supabase_url and 
        settings.supabase_anon_key and 
        not settings.supabase_url.endswith("example.supabase.co") and
        not settings.supabase_anon_key.endswith("example")):
        supabase = create_client(
            settings.supabase_url, 
            settings.supabase_anon_key
        )
        logger.info("Supabase client initialized successfully")
    else:
        logger.warning("Supabase not configured - working without database")
        supabase = None
except Exception as e:
    logger.warning(f"Supabase client creation failed: {e}")
    supabase = None

# Хранилище активных проектов (в продакшне использовать Redis)
active_projects: Dict[str, GPTPilotIntegration] = {}

# === ОБРАБОТЧИКИ ОШИБОК ===

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Обработчик ошибок валидации Pydantic"""
    logger.warning(f"Validation error: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            error="validation_error",
            message="Ошибка валидации входных данных",
            details={"errors": exc.errors()}
        ).dict()
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Обработчик HTTP исключений"""
    logger.error(f"HTTP error {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="http_error",
            message=str(exc.detail),
            details={"status_code": exc.status_code}
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Обработчик общих исключений"""
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="internal_error",
            message="Внутренняя ошибка сервера",
            details={"error_id": str(uuid.uuid4())}
        ).dict()
    )

# === БАЗОВЫЕ ЭНДПОИНТЫ ===

@app.options("/{path:path}")
async def options_handler(path: str):
    """Обработчик для CORS preflight запросов"""
    return JSONResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Requested-With",
            "Access-Control-Allow-Credentials": "true"
        }
    )

@app.get("/", response_model=BaseResponse)
async def root():
    """Корневой эндпоинт"""
    return BaseResponse(
        success=True,
        message="🚀 Samokoder Backend API",
        timestamp=datetime.now()
    )

@app.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Проверка здоровья сервиса"""
    health_status = monitoring.get_health_status()
    return HealthCheckResponse(
        status=health_status.get("status", "unknown"),
        version="1.0.0",
        uptime=health_status.get("uptime", 0),
        services=health_status.get("services", {})
    )

@app.get("/health/detailed", response_model=DetailedHealthResponse)
async def detailed_health_check():
    """Детальная проверка здоровья всех компонентов"""
    from backend.monitoring import check_external_services_health
    
    health_status = monitoring.get_health_status()
    external_services = await check_external_services_health()
    connection_pools_health = await connection_pool_manager.health_check()
    
    return DetailedHealthResponse(
        status=health_status.get("status", "unknown"),
        version="1.0.0",
        uptime=health_status.get("uptime", 0),
        services=health_status.get("services", {}),
        external_services=external_services,
        active_projects=len(active_projects),
        memory_usage=health_status.get("memory_usage", {}),
        disk_usage=health_status.get("disk_usage", {}),
        connection_pools=connection_pools_health
    )

@app.get("/metrics", response_model=MetricsResponse)
async def metrics():
    """Prometheus метрики"""
    metrics_data = get_metrics_response()
    return MetricsResponse(**metrics_data)

# === АУТЕНТИФИКАЦИЯ ===

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    rate_limit: dict = Depends(auth_rate_limit)
):
    """Вход через Supabase Auth (или mock для тестирования)"""
    try:
        # Если Supabase недоступен, используем mock аутентификацию
        if not supabase or settings.supabase_url.endswith("example.supabase.co"):
            logger.warning("Supabase not available, using mock authentication")
            return LoginResponse(
                message="Успешный вход (mock режим)",
                user={
                    "id": f"mock_user_{credentials.email}",
                    "email": credentials.email,
                    "full_name": None,
                    "avatar_url": None,
                    "subscription_tier": "free",
                    "subscription_status": "active",
                    "api_credits_balance": 0.0,
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                },
                access_token=f"mock_token_{credentials.email}",
                expires_in=3600
            )
        
        response = supabase.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })
        
        if response.user:
            logger.info(f"User {response.user.email} logged in successfully")
            return LoginResponse(
                message="Успешный вход",
                user={
                    "id": response.user.id,
                    "email": response.user.email,
                    "full_name": response.user.user_metadata.get("full_name"),
                    "avatar_url": response.user.user_metadata.get("avatar_url"),
                    "subscription_tier": "free",
                    "subscription_status": "active",
                    "api_credits_balance": 0.0,
                    "created_at": datetime.fromisoformat(response.user.created_at.replace('Z', '+00:00')),
                    "updated_at": datetime.now()
                },
                access_token=response.session.access_token,
                expires_in=response.session.expires_in
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверные учетные данные"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка входа в систему"
        )

@app.post("/api/auth/logout", response_model=BaseResponse)
async def logout(current_user: dict = Depends(get_current_user)):
    """Выход из системы"""
    try:
        if supabase:
            supabase.auth.sign_out()
        logger.info(f"User {current_user.get('email')} logged out")
        return BaseResponse(
            success=True,
            message="Успешный выход"
        )
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка выхода из системы"
        )

@app.get("/api/auth/user", response_model=dict)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Получить информацию о текущем пользователе"""
    return {
        "user": current_user,
        "timestamp": datetime.now().isoformat()
    }

# === УПРАВЛЕНИЕ ПРОЕКТАМИ ===

@app.get("/api/projects", response_model=ProjectListResponse)
async def get_projects(
    request: ProjectListRequest = Depends(),
    current_user: dict = Depends(get_current_user)
):
    """Получить список проектов пользователя с пагинацией"""
    try:
        if not supabase:
            # Mock режим
            return ProjectListResponse(
                projects=[],
                total_count=0,
                page=request.page,
                limit=request.limit
            )
        
        # Подсчет общего количества
        count_query = supabase.table("projects").select("id", count="exact").eq("user_id", current_user["id"])
        if request.status:
            count_query = count_query.eq("status", request.status.value)
        if request.search:
            count_query = count_query.or_(f"name.ilike.%{request.search}%,description.ilike.%{request.search}%")
        
        count_response = count_query.execute()
        total_count = count_response.count or 0
        
        # Получение проектов с пагинацией
        query = supabase.table("projects").select("*").eq("user_id", current_user["id"])
        
        if request.status:
            query = query.eq("status", request.status.value)
        if request.search:
            query = query.or_(f"name.ilike.%{request.search}%,description.ilike.%{request.search}%")
        
        query = query.order("created_at", desc=True)
        query = query.range(
            (request.page - 1) * request.limit,
            request.page * request.limit - 1
        )
        
        response = query.execute()
        
        projects = []
        for project_data in response.data or []:
            projects.append(ProjectResponse(**project_data))
        
        return ProjectListResponse(
            projects=projects,
            total_count=total_count,
            page=request.page,
            limit=request.limit
        )
        
    except Exception as e:
        logger.error(f"Error getting projects: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка получения проектов"
        )

@app.post("/api/projects", response_model=ProjectCreateResponse)
async def create_project(
    project_data: ProjectCreateRequest,
    current_user: dict = Depends(get_current_user),
    background_tasks: BackgroundTasks = None,
    rate_limit: dict = Depends(api_rate_limit)
):
    """Создать новый проект с валидацией"""
    
    project_id = str(uuid.uuid4())
    user_id = current_user["id"]
    
    try:
        # Получаем API ключи пользователя
        if supabase:
            user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
            user_api_keys = {
                row['provider']: row['api_key_decrypted'] 
                for row in user_keys_response.data or []
            }
        else:
            user_api_keys = {}
        
        # Создаем интеграцию GPT-Pilot
        pilot_integration = GPTPilotIntegration(project_id, user_id, user_api_keys)
        
        # Инициализируем проект
        init_result = await pilot_integration.initialize_project(
            app_name=project_data.name,
            app_description=project_data.description
        )
        
        if init_result["status"] == "error":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=init_result["message"]
            )
        
        # Сохраняем в базу (если Supabase доступен)
        if supabase:
            project_record = {
                "id": project_id,
                "user_id": user_id,
                "name": project_data.name,
                "description": project_data.description,
                "status": "created",
                "tech_stack": project_data.tech_stack or {},
                "ai_config": project_data.ai_config or {},
                "created_at": datetime.now().isoformat()
            }
            supabase.table("projects").insert(project_record).execute()
        
        # Сохраняем активный проект
        active_projects[project_id] = pilot_integration
        
        logger.info(f"Project {project_id} created successfully for user {user_id}")
        
        return ProjectCreateResponse(
            message="Проект создан, готов к работе",
            project_id=project_id,
            status="created",
            workspace=init_result["workspace"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating project: {e}")
        # Очищаем активные проекты в случае ошибки
        if project_id in active_projects:
            del active_projects[project_id]
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка создания проекта"
        )

@app.get("/api/projects/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить детали проекта"""
    
    try:
        if supabase:
            response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"]).single().execute()
            
            if not response.data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Проект не найден"
                )
            
            return ProjectResponse(**response.data)
        else:
            # Mock режим
            if project_id not in active_projects:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Проект не найден"
                )
            
            return ProjectResponse(
                id=project_id,
                user_id=current_user["id"],
                name="Mock Project",
                description="Mock project description",
                status="active",
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка получения проекта"
        )

@app.delete("/api/projects/{project_id}", response_model=BaseResponse)
async def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Удалить проект"""
    
    try:
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="База данных недоступна"
            )
        
        # Проверяем, что проект принадлежит пользователю
        project_response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"]).single().execute()
        
        if not project_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Проект не найден"
            )
        
        # Удаляем из активных проектов
        if project_id in active_projects:
            del active_projects[project_id]
        
        # Удаляем из базы
        supabase.table("projects").delete().eq("id", project_id).execute()
        
        logger.info(f"Project {project_id} deleted successfully")
        
        return BaseResponse(
            success=True,
            message="Проект успешно удален"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка удаления проекта"
        )

# === ЧАТ И ГЕНЕРАЦИЯ ===

@app.post("/api/projects/{project_id}/chat")
async def chat_with_project(
    project_id: str,
    chat_data: ChatRequest,
    current_user: dict = Depends(get_current_user)
):
    """Отправить сообщение агентам проекта"""
    
    if project_id not in active_projects:
        # Загружаем проект из базы если не в памяти
        await load_project_to_memory(project_id, current_user["id"])
    
    if project_id not in active_projects:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Проект не найден или не активен"
        )
    
    pilot_integration = active_projects[project_id]
    
    async def stream_response():
        try:
            async for update in pilot_integration.chat_with_agents(
                message=chat_data.message,
                context=chat_data.context
            ):
                yield f"data: {json.dumps(update)}\n\n"
        except Exception as e:
            logger.error(f"Error in chat stream: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': 'Ошибка в работе агентов'})}\n\n"
    
    return StreamingResponse(
        stream_response(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )

# === AI СЕРВИС ===

@app.post("/api/ai/chat", response_model=AIResponse)
async def ai_chat(
    chat_data: ChatRequest,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(ai_rate_limit)
):
    """Чат с AI через централизованный сервис"""
    
    try:
        # Получаем API ключи пользователя
        if supabase:
            user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", current_user["id"]).eq("is_active", True).execute()
            user_api_keys = {
                row['provider']: row['api_key_decrypted'] 
                for row in user_keys_response.data or []
            }
        else:
            user_api_keys = {}
        
        # Создаем AI сервис
        ai_service = get_ai_service(current_user["id"], user_api_keys)
        
        # Формируем сообщения
        messages = [
            {"role": "system", "content": "Ты - AI помощник для создания приложений. Отвечай кратко и по делу."},
            {"role": "user", "content": chat_data.message}
        ]
        
        # Выполняем запрос
        response = await ai_service.route_request(
            messages=messages,
            model=chat_data.model,
            provider=chat_data.provider.value if chat_data.provider else None,
            project_id="",
            max_tokens=chat_data.max_tokens,
            temperature=chat_data.temperature
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
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Ошибка AI сервиса"
            )
        
        return AIResponse(
            content=response.content,
            provider=response.provider,
            model=response.model,
            tokens_used=response.tokens_used,
            cost_usd=response.cost_usd,
            response_time=response.response_time
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI chat error: {e}")
        monitoring.log_error(e, {"user_id": current_user["id"], "action": "ai_chat"})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка AI чата"
        )

@app.get("/api/ai/usage", response_model=AIUsageStatsResponse)
async def get_ai_usage(current_user: dict = Depends(get_current_user)):
    """Получение статистики использования AI"""
    
    try:
        # Получаем API ключи пользователя
        if supabase:
            user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", current_user["id"]).eq("is_active", True).execute()
            user_api_keys = {
                row['provider']: row['api_key_decrypted'] 
                for row in user_keys_response.data or []
            }
        else:
            user_api_keys = {}
        
        # Создаем AI сервис
        ai_service = get_ai_service(current_user["id"], user_api_keys)
        
        # Получаем статистику
        stats = await ai_service.get_usage_stats()
        
        return AIUsageStatsResponse(**stats)
        
    except Exception as e:
        logger.error(f"AI usage stats error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка получения статистики"
        )

@app.get("/api/ai/providers", response_model=AIProvidersResponse)
async def get_ai_providers():
    """Получение списка доступных AI провайдеров"""
    
    providers = [
        {
            "id": "openrouter",
            "name": "OpenRouter",
            "display_name": "OpenRouter",
            "description": "Доступ к множеству AI моделей",
            "website": "https://openrouter.ai",
            "requires_key": True,
            "free_models": ["deepseek/deepseek-v3", "qwen/qwen-2.5-coder-32b"]
        },
        {
            "id": "openai",
            "name": "OpenAI",
            "display_name": "OpenAI",
            "description": "GPT-4o и GPT-4o-mini",
            "website": "https://openai.com",
            "requires_key": True,
            "free_models": []
        },
        {
            "id": "anthropic",
            "name": "Anthropic",
            "display_name": "Anthropic",
            "description": "Claude 3 Haiku и Sonnet",
            "website": "https://anthropic.com",
            "requires_key": True,
            "free_models": []
        },
        {
            "id": "groq",
            "name": "Groq",
            "display_name": "Groq",
            "description": "Быстрые Llama модели",
            "website": "https://groq.com",
            "requires_key": True,
            "free_models": ["llama-3-8b-8192", "llama-3-70b-8192"]
        }
    ]
    
    return AIProvidersResponse(providers=providers)

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

async def load_project_to_memory(project_id: str, user_id: str):
    """Загружает проект в память из базы данных"""
    
    try:
        if not supabase:
            return
        
        # Получаем данные проекта
        project_response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).single().execute()
        
        if not project_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Проект не найден"
            )
        
        project_data = project_response.data
        
        # Получаем API ключи пользователя
        user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
        user_api_keys = {
            row['provider']: row['api_key_decrypted']
            for row in user_keys_response.data or []
        }
        
        # Создаем интеграцию
        pilot_integration = GPTPilotIntegration(project_id, user_id, user_api_keys)
        
        # Если проект уже создан, восстанавливаем его состояние
        if project_data['status'] != 'created':
            await pilot_integration.restore_from_workspace()
        
        active_projects[project_id] = pilot_integration
        
        logger.info(f"Project {project_id} loaded to memory successfully")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading project to memory: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка загрузки проекта"
        )

# === MIDDLEWARE ДЛЯ ЛОГИРОВАНИЯ ===

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Middleware для логирования запросов"""
    start_time = datetime.now()
    
    response = await call_next(request)
    
    process_time = (datetime.now() - start_time).total_seconds()
    
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.3f}s"
    )
    
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main_improved:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )