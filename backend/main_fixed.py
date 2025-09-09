from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

from config.settings import settings
from backend.services.gpt_pilot_wrapper_fixed import SamokoderGPTPilot
from backend.auth.dependencies import get_current_user

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase клиент
supabase: Client = create_client(
    settings.supabase_url, 
    settings.supabase_anon_key
)

# Хранилище активных проектов (в продакшне использовать Redis)
active_projects: Dict[str, SamokoderGPTPilot] = {}

# === БАЗОВЫЕ ЭНДПОИНТЫ ===

@app.get("/")
async def root():
    """Корневой эндпоинт"""
    return {
        "message": "🚀 Samokoder Backend API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Проверка здоровья сервиса"""
    try:
        # Проверяем подключение к Supabase
        supabase.table("profiles").select("id").limit(1).execute()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "active_projects": len(active_projects),
            "database": "connected"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "active_projects": len(active_projects),
            "database": "disconnected",
            "error": str(e)
        }

# === АУТЕНТИФИКАЦИЯ ===

@app.post("/api/auth/login")
async def login(credentials: dict):
    """Вход через Supabase Auth"""
    try:
        if not credentials.get("email") or not credentials.get("password"):
            raise HTTPException(status_code=400, detail="Email и пароль обязательны")
        
        response = supabase.auth.sign_in_with_password({
            "email": credentials["email"],
            "password": credentials["password"]
        })
        
        if response.user:
            logger.info(f"User {response.user.email} logged in successfully")
            return {
                "message": "Успешный вход",
                "user": response.user,
                "session": response.session
            }
        else:
            raise HTTPException(status_code=401, detail="Неверные учетные данные")
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=401, detail=f"Ошибка входа: {str(e)}")

@app.post("/api/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Выход из системы"""
    try:
        supabase.auth.sign_out()
        logger.info(f"User {current_user.get('email')} logged out")
        return {"message": "Успешный выход"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
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
        response = supabase.table("projects").select("*").eq("user_id", current_user["id"]).order("created_at", desc=True).execute()
        
        if not response.data:
            return {
                "projects": [],
                "total_count": 0
            }
        
        return {
            "projects": response.data,
            "total_count": len(response.data)
        }
    except Exception as e:
        logger.error(f"Error getting projects: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения проектов: {str(e)}")

@app.post("/api/projects")
async def create_project(
    project_data: dict,
    current_user: dict = Depends(get_current_user),
    background_tasks: BackgroundTasks = None
):
    """Создать новый проект"""
    
    # Валидация входных данных
    if not project_data.get("name") or not project_data.get("description"):
        raise HTTPException(status_code=400, detail="Название и описание проекта обязательны")
    
    project_id = str(uuid.uuid4())
    user_id = current_user["id"]
    
    try:
        # Получаем API ключи пользователя
        user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
        user_api_keys = {
            row['provider']: row['api_key_decrypted'] 
            for row in user_keys_response.data
        } if user_keys_response.data else {}
        
        # Создаем обертку GPT-Pilot
        pilot_wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
        
        # Инициализируем проект
        init_result = await pilot_wrapper.initialize_project(
            app_description=project_data["description"],
            app_name=project_data["name"]
        )
        
        if init_result["status"] == "error":
            raise HTTPException(status_code=400, detail=init_result["message"])
        
        # Сохраняем в базу
        project_record = {
            "id": project_id,
            "user_id": user_id,
            "name": project_data["name"],
            "description": project_data["description"], 
            "status": "created",
            "created_at": datetime.now().isoformat()
        }
        
        supabase.table("projects").insert(project_record).execute()
        
        # Сохраняем активный проект
        active_projects[project_id] = pilot_wrapper
        
        logger.info(f"Project {project_id} created successfully for user {user_id}")
        
        return {
            "project_id": project_id,
            "status": "created",
            "message": "Проект создан, готов к работе",
            "workspace": init_result["workspace"]
        }
        
    except Exception as e:
        logger.error(f"Error creating project: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка создания проекта: {str(e)}")

@app.get("/api/projects/{project_id}")
async def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить детали проекта"""
    
    try:
        response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"]).single().execute()
        
        if not response.data:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        return {
            "project": response.data,
            "is_active": project_id in active_projects
        }
        
    except Exception as e:
        logger.error(f"Error getting project {project_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения проекта: {str(e)}")

@app.delete("/api/projects/{project_id}")
async def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Удалить проект"""
    
    try:
        # Проверяем, что проект принадлежит пользователю
        project_response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"]).single().execute()
        
        if not project_response.data:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        # Удаляем из активных проектов
        if project_id in active_projects:
            del active_projects[project_id]
        
        # Удаляем из базы
        supabase.table("projects").delete().eq("id", project_id).execute()
        
        logger.info(f"Project {project_id} deleted successfully")
        
        return {"message": "Проект успешно удален"}
        
    except Exception as e:
        logger.error(f"Error deleting project {project_id}: {e}")
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
            logger.error(f"Error in chat stream: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
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
        logger.error(f"Error updating project status: {e}")
    
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
            logger.error(f"Error in generation stream: {e}")
            # Обновляем статус при ошибке
            try:
                supabase.table("projects").update({
                    "status": "error",
                    "updated_at": datetime.now().isoformat()
                }).eq("id", project_id).execute()
            except Exception as update_error:
                logger.error(f"Error updating project status on error: {update_error}")
            
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
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
        file_tree = pilot_wrapper.get_project_files()
        
        return {
            "project_id": project_id,
            "files": file_tree,
            "updated_at": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting project files: {e}")
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
        logger.error(f"Error getting file content: {e}")
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
        
        logger.info(f"Project {project_id} exported successfully")
        
        return FileResponse(
            zip_path,
            media_type="application/zip",
            filename=f"samokoder_project_{project_id}.zip"
        )
    except Exception as e:
        logger.error(f"Error exporting project: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка экспорта: {str(e)}")

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

async def load_project_to_memory(project_id: str, user_id: str):
    """Загружает проект в память из базы данных"""
    
    try:
        # Получаем данные проекта
        project_response = supabase.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).single().execute()
        
        if not project_response.data:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project_data = project_response.data
        
        # Получаем API ключи пользователя
        user_keys_response = supabase.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
        user_api_keys = {
            row['provider']: row['api_key_decrypted']
            for row in user_keys_response.data
        } if user_keys_response.data else {}
        
        # Создаем wrapper
        pilot_wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
        
        # Если проект уже создан, восстанавливаем его состояние
        if project_data['status'] != 'created':
            await pilot_wrapper.restore_from_workspace()
        
        active_projects[project_id] = pilot_wrapper
        
        logger.info(f"Project {project_id} loaded to memory successfully")
        
    except Exception as e:
        logger.error(f"Error loading project to memory: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка загрузки проекта: {str(e)}")

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
        "backend.main_fixed:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )