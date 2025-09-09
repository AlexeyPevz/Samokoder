#!/usr/bin/env python3
"""
Тестовая версия сервера без Supabase для проверки исправлений
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Создаем FastAPI приложение
app = FastAPI(
    title="Samokoder Backend API (Test)",
    description="AI-платформа для создания full-stack приложений - Тестовая версия",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Хранилище активных проектов (в продакшне использовать Redis)
active_projects: Dict[str, Dict] = {}

# === БАЗОВЫЕ ЭНДПОИНТЫ ===

@app.get("/")
async def root():
    """Корневой эндпойнт"""
    return {
        "message": "Samokoder Backend API (Test Version)",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check эндпойнт"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "environment": "test"
    }

@app.get("/api/info")
async def api_info():
    """Информация об API"""
    return {
        "name": "Samokoder Backend API",
        "version": "1.0.0",
        "description": "AI-платформа для создания full-stack приложений",
        "status": "running",
        "environment": "test",
        "timestamp": datetime.now().isoformat()
    }

# === ПРОЕКТЫ ===

@app.post("/api/projects", status_code=201)
async def create_project(
    project_name: str,
    app_description: str,
    user_id: str = "test_user"
):
    """Создать новый проект (тестовая версия)"""
    try:
        project_id = f"proj_{user_id}_{len(active_projects) + 1}"
        
        # Создаем тестовый проект
        project_data = {
            "id": project_id,
            "user_id": user_id,
            "name": project_name,
            "description": app_description,
            "status": "created",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        active_projects[project_id] = project_data
        
        logger.info(f"Test project {project_id} created successfully for user {user_id}")
        
        return {
            "project_id": project_id,
            "status": "created",
            "message": "Проект создан, готов к работе (тестовая версия)",
            "workspace": f"workspaces/{user_id}/{project_id}"
        }
        
    except Exception as e:
        logger.error(f"Error creating test project: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка создания проекта: {str(e)}")

@app.get("/api/projects")
async def get_projects(user_id: str = "test_user"):
    """Получить список проектов (тестовая версия)"""
    try:
        user_projects = [p for p in active_projects.values() if p["user_id"] == user_id]
        
        return {
            "projects": user_projects,
            "total": len(user_projects),
            "message": "Проекты получены (тестовая версия)"
        }
        
    except Exception as e:
        logger.error(f"Error getting test projects: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения проектов: {str(e)}")

@app.get("/api/projects/{project_id}")
async def get_project(project_id: str, user_id: str = "test_user"):
    """Получить детали проекта (тестовая версия)"""
    try:
        if project_id not in active_projects:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project = active_projects[project_id]
        
        if project["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        
        return {
            "project": project,
            "is_active": project_id in active_projects,
            "message": "Проект получен (тестовая версия)"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting test project: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения проекта: {str(e)}")

@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str, user_id: str = "test_user"):
    """Удалить проект (тестовая версия)"""
    try:
        if project_id not in active_projects:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project = active_projects[project_id]
        
        if project["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        
        # Удаляем из активных проектов
        del active_projects[project_id]
        
        logger.info(f"Test project {project_id} deleted successfully")
        
        return {"message": "Проект успешно удален (тестовая версия)"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting test project: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка удаления проекта: {str(e)}")

# === ЧАТ ===

@app.post("/api/projects/{project_id}/chat")
async def chat_with_project(project_id: str, chat_data: dict, user_id: str = "test_user"):
    """Чат с проектом (тестовая версия)"""
    try:
        if project_id not in active_projects:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project = active_projects[project_id]
        
        if project["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        
        message = chat_data.get("message", "")
        context = chat_data.get("context", "chat")
        
        async def stream_response():
            try:
                # Симулируем ответ агентов
                yield f"data: {json.dumps({'type': 'status', 'message': 'Агенты анализируют запрос...', 'timestamp': datetime.now().isoformat()})}\n\n"
                await asyncio.sleep(0.5)
                
                yield f"data: {json.dumps({'type': 'agent_response', 'agent': 'Product Owner', 'message': f'Понял ваш запрос: {message}', 'timestamp': datetime.now().isoformat()})}\n\n"
                await asyncio.sleep(0.5)
                
                yield f"data: {json.dumps({'type': 'agent_response', 'agent': 'Architect', 'message': 'Анализирую архитектуру...', 'timestamp': datetime.now().isoformat()})}\n\n"
                await asyncio.sleep(0.5)
                
                yield f"data: {json.dumps({'type': 'agent_response', 'agent': 'Developer', 'message': 'Готов к реализации...', 'timestamp': datetime.now().isoformat()})}\n\n"
                await asyncio.sleep(0.5)
                
                yield f"data: {json.dumps({'type': 'completion', 'message': 'Анализ завершен (тестовая версия)', 'timestamp': datetime.now().isoformat()})}\n\n"
                
            except Exception as e:
                logger.error(f"Error in test chat stream: {e}")
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        
        return StreamingResponse(
            stream_response(),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in test chat: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка чата: {str(e)}")

# === ГЕНЕРАЦИЯ ===

@app.post("/api/projects/{project_id}/generate")
async def generate_project(project_id: str, user_id: str = "test_user"):
    """Генерация проекта (тестовая версия)"""
    try:
        if project_id not in active_projects:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project = active_projects[project_id]
        
        if project["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        
        # Обновляем статус
        project["status"] = "generating"
        project["updated_at"] = datetime.now().isoformat()
        
        async def stream_generation():
            try:
                # Симулируем процесс генерации
                steps = [
                    "Инициализация проекта...",
                    "Создание структуры файлов...",
                    "Генерация компонентов...",
                    "Настройка зависимостей...",
                    "Создание документации...",
                    "Финальная проверка..."
                ]
                
                for i, step in enumerate(steps):
                    progress = int((i + 1) / len(steps) * 100)
                    yield f"data: {json.dumps({'type': 'progress', 'message': step, 'progress': progress, 'timestamp': datetime.now().isoformat()})}\n\n"
                    await asyncio.sleep(1)
                
                # Финальное обновление статуса
                project["status"] = "completed"
                project["updated_at"] = datetime.now().isoformat()
                
                yield f"data: {json.dumps({'type': 'completion', 'message': 'Проект готов! (тестовая версия)', 'progress': 100, 'timestamp': datetime.now().isoformat()})}\n\n"
                
            except Exception as e:
                logger.error(f"Error in test generation stream: {e}")
                # Обновляем статус при ошибке
                project["status"] = "error"
                project["updated_at"] = datetime.now().isoformat()
                
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        
        return StreamingResponse(
            stream_generation(),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in test generation: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка генерации: {str(e)}")

# === ФАЙЛЫ ===

@app.get("/api/projects/{project_id}/files")
async def get_project_files(project_id: str, user_id: str = "test_user"):
    """Получить файлы проекта (тестовая версия)"""
    try:
        if project_id not in active_projects:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project = active_projects[project_id]
        
        if project["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        
        # Симулируем структуру файлов
        files = {
            "src": {
                "App.js": {"type": "file", "size": 1024},
                "index.js": {"type": "file", "size": 512},
                "components": {
                    "Header.js": {"type": "file", "size": 768},
                    "Footer.js": {"type": "file", "size": 512}
                }
            },
            "public": {
                "index.html": {"type": "file", "size": 2048},
                "favicon.ico": {"type": "file", "size": 1024}
            },
            "package.json": {"type": "file", "size": 1024}
        }
        
        return {
            "files": files,
            "total_files": 7,
            "message": "Файлы получены (тестовая версия)"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting test project files: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения файлов: {str(e)}")

@app.get("/api/projects/{project_id}/files/{file_path:path}")
async def get_file_content(project_id: str, file_path: str, user_id: str = "test_user"):
    """Получить содержимое файла (тестовая версия)"""
    try:
        if project_id not in active_projects:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project = active_projects[project_id]
        
        if project["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        
        # Симулируем содержимое файла
        content = f"// Тестовое содержимое файла {file_path}\n// Проект: {project['name']}\n// Описание: {project['description']}\n\nconsole.log('Hello from {file_path}!');"
        
        return {
            "file_path": file_path,
            "content": content,
            "size": len(content),
            "message": "Содержимое файла получено (тестовая версия)"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting test file content: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения файла: {str(e)}")

# === ЭКСПОРТ ===

@app.get("/api/projects/{project_id}/export")
async def export_project(project_id: str, user_id: str = "test_user"):
    """Экспорт проекта (тестовая версия)"""
    try:
        if project_id not in active_projects:
            raise HTTPException(status_code=404, detail="Проект не найден")
        
        project = active_projects[project_id]
        
        if project["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        
        # Создаем тестовый ZIP файл
        import zipfile
        import tempfile
        import os
        
        # Создаем временный файл
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            with zipfile.ZipFile(temp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Добавляем тестовые файлы
                zipf.writestr("README.md", f"# {project['name']}\n\n{project['description']}\n\nЭто тестовая версия проекта.")
                zipf.writestr("package.json", '{"name": "' + project['name'].lower().replace(' ', '-') + '", "version": "1.0.0"}')
                zipf.writestr("src/App.js", "// Тестовый React компонент\nconsole.log('Hello World!');")
            
            # Возвращаем файл
            return FileResponse(
                temp_file.name,
                media_type="application/zip",
                filename=f"{project['name'].lower().replace(' ', '-')}_test.zip",
                background=BackgroundTasks()
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting test project: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка экспорта: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Запуск тестового сервера Samokoder...")
    print("📍 Host: 0.0.0.0")
    print("🔌 Port: 8000")
    print("🌍 Environment: test")
    print("📚 Docs: http://0.0.0.0:8000/docs")
    print("--------------------------------------------------")
    
    uvicorn.run(
        "test_server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )