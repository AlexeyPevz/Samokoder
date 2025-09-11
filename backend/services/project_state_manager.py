"""
Project State Manager - управление состоянием проектов
Заменяет глобальную переменную active_projects на централизованное управление
"""

import asyncio
import logging
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import json
import threading
from contextlib import asynccontextmanager

from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot
from backend.services.supabase_manager import execute_supabase_operation

logger = logging.getLogger(__name__)

@dataclass
class ProjectState:
    """Состояние проекта"""
    project_id: str
    user_id: str
    pilot_wrapper: SamokoderGPTPilot
    created_at: datetime
    last_accessed: datetime
    is_active: bool = True

class ProjectStateManager:
    """Менеджер состояния проектов с автоматической очисткой"""
    
    def __init__(self, max_projects: int = 100, idle_timeout: int = 3600):
        self.max_projects = max_projects
        self.idle_timeout = idle_timeout  # 1 час
        self._projects: Dict[str, ProjectState] = {}
        self._lock = threading.RLock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._initialized = False
    
    async def initialize(self):
        """Инициализация менеджера"""
        if self._initialized:
            return
        
        # Запускаем задачу очистки неактивных проектов
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._initialized = True
        logger.info("Project state manager initialized")
    
    async def add_project(self, project_id: str, user_id: str, pilot_wrapper: SamokoderGPTPilot) -> bool:
        """Добавить проект в активные"""
        with self._lock:
            # Проверяем лимит проектов
            if len(self._projects) >= self.max_projects:
                # Удаляем самый старый неактивный проект
                await self._remove_oldest_project()
            
            # Добавляем проект
            self._projects[project_id] = ProjectState(
                project_id=project_id,
                user_id=user_id,
                pilot_wrapper=pilot_wrapper,
                created_at=datetime.now(),
                last_accessed=datetime.now()
            )
            
            logger.info(f"Project {project_id} added to active projects")
            return True
    
    async def get_project(self, project_id: str, user_id: str) -> Optional[SamokoderGPTPilot]:
        """Получить проект по ID"""
        with self._lock:
            project_state = self._projects.get(project_id)
            
            if not project_state:
                # Пытаемся загрузить проект из базы
                await self._load_project_from_db(project_id, user_id)
                project_state = self._projects.get(project_id)
            
            if project_state and project_state.user_id == user_id:
                # Обновляем время последнего доступа
                project_state.last_accessed = datetime.now()
                return project_state.pilot_wrapper
            
            return None
    
    async def remove_project(self, project_id: str, user_id: str) -> bool:
        """Удалить проект"""
        with self._lock:
            project_state = self._projects.get(project_id)
            
            if project_state and project_state.user_id == user_id:
                # Очищаем ресурсы проекта
                try:
                    if hasattr(project_state.pilot_wrapper, 'cleanup'):
                        await project_state.pilot_wrapper.cleanup()
                except Exception as e:
                    logger.warning(f"Error cleaning up project {project_id}: {e}")
                
                del self._projects[project_id]
                logger.info(f"Project {project_id} removed from active projects")
                return True
            
            return False
    
    async def list_user_projects(self, user_id: str) -> List[Dict[str, Any]]:
        """Получить список активных проектов пользователя"""
        with self._lock:
            user_projects = []
            for project_state in self._projects.values():
                if project_state.user_id == user_id and project_state.is_active:
                    user_projects.append({
                        "project_id": project_state.project_id,
                        "created_at": project_state.created_at.isoformat(),
                        "last_accessed": project_state.last_accessed.isoformat(),
                        "is_active": True
                    })
            
            return user_projects
    
    async def is_project_active(self, project_id: str, user_id: str) -> bool:
        """Проверить, активен ли проект"""
        with self._lock:
            project_state = self._projects.get(project_id)
            return project_state is not None and project_state.user_id == user_id and project_state.is_active
    
    async def _load_project_from_db(self, project_id: str, user_id: str):
        """Загрузить проект из базы данных"""
        try:
            # Получаем данные проекта из базы
            response = await execute_supabase_operation(
                lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).single().execute(),
                "anon"
            )
            
            if not response.data:
                logger.warning(f"Project {project_id} not found in database")
                return
            
            project_data = response.data
            
            # Получаем API ключи пользователя
            user_api_keys = {}
            user_keys_response = await execute_supabase_operation(
                lambda client: client.table("user_api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute(),
                "anon"
            )
            
            if user_keys_response.data:
                from backend.services.encryption_service import get_encryption_service
                encryption_service = get_encryption_service()
                
                for row in user_keys_response.data:
                    provider_name = row.get('provider_name', 'unknown')
                    try:
                        decrypted_key = encryption_service.decrypt_api_key(
                            row['api_key_encrypted'], 
                            user_id
                        )
                        user_api_keys[provider_name] = decrypted_key
                    except Exception as e:
                        logger.warning(f"Failed to decrypt API key for {provider_name}: {e}")
                        continue
            
            # Создаем pilot wrapper
            pilot_wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
            
            # Если проект уже создан, восстанавливаем его состояние
            if project_data.get('status') != 'draft':
                try:
                    await pilot_wrapper.restore_from_workspace()
                except Exception as e:
                    logger.warning(f"Failed to restore project {project_id} from workspace: {e}")
            
            # Добавляем в активные проекты
            await self.add_project(project_id, user_id, pilot_wrapper)
            logger.info(f"Project {project_id} loaded from database")
            
        except Exception as e:
            logger.error(f"Failed to load project {project_id} from database: {e}")
    
    async def _remove_oldest_project(self):
        """Удалить самый старый неактивный проект"""
        oldest_project = None
        oldest_time = None
        
        for project_id, project_state in self._projects.items():
            if oldest_time is None or project_state.last_accessed < oldest_time:
                oldest_time = project_state.last_accessed
                oldest_project = project_id
        
        if oldest_project:
            await self.remove_project(oldest_project, self._projects[oldest_project].user_id)
            logger.info(f"Removed oldest project {oldest_project} to make room")
    
    async def _cleanup_loop(self):
        """Цикл очистки неактивных проектов"""
        while True:
            try:
                await asyncio.sleep(300)  # Проверяем каждые 5 минут
                await self._cleanup_inactive_projects()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def _cleanup_inactive_projects(self):
        """Очистка неактивных проектов"""
        with self._lock:
            now = datetime.now()
            to_remove = []
            
            for project_id, project_state in self._projects.items():
                if (now - project_state.last_accessed).total_seconds() > self.idle_timeout:
                    to_remove.append(project_id)
            
            for project_id in to_remove:
                await self.remove_project(project_id, self._projects[project_id].user_id)
                logger.info(f"Cleaned up inactive project {project_id}")
    
    async def get_stats(self) -> Dict[str, Any]:
        """Получить статистику менеджера"""
        with self._lock:
            return {
                "total_projects": len(self._projects),
                "max_projects": self.max_projects,
                "idle_timeout": self.idle_timeout,
                "projects": [
                    {
                        "project_id": project_state.project_id,
                        "user_id": project_state.user_id,
                        "created_at": project_state.created_at.isoformat(),
                        "last_accessed": project_state.last_accessed.isoformat(),
                        "is_active": project_state.is_active
                    }
                    for project_state in self._projects.values()
                ]
            }
    
    async def close(self):
        """Закрытие менеджера"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Очищаем все проекты
        with self._lock:
            for project_state in self._projects.values():
                try:
                    if hasattr(project_state.pilot_wrapper, 'cleanup'):
                        await project_state.pilot_wrapper.cleanup()
                except Exception as e:
                    logger.warning(f"Error cleaning up project {project_state.project_id}: {e}")
            
            self._projects.clear()
        
        self._initialized = False
        logger.info("Project state manager closed")

# Глобальный экземпляр менеджера
project_state_manager = ProjectStateManager()

# Удобные функции для использования
async def get_active_project(project_id: str, user_id: str) -> Optional[SamokoderGPTPilot]:
    """Получить активный проект"""
    return await project_state_manager.get_project(project_id, user_id)

async def add_active_project(project_id: str, user_id: str, pilot_wrapper: SamokoderGPTPilot) -> bool:
    """Добавить активный проект"""
    return await project_state_manager.add_project(project_id, user_id, pilot_wrapper)

async def remove_active_project(project_id: str, user_id: str) -> bool:
    """Удалить активный проект"""
    return await project_state_manager.remove_project(project_id, user_id)

async def is_project_active(project_id: str, user_id: str) -> bool:
    """Проверить, активен ли проект"""
    return await project_state_manager.is_project_active(project_id, user_id)

@asynccontextmanager
async def project_context(project_id: str, user_id: str):
    """Контекстный менеджер для работы с проектом"""
    project = await get_active_project(project_id, user_id)
    if not project:
        raise ValueError(f"Project {project_id} not found or not active")
    
    try:
        yield project
    except Exception as e:
        logger.error(f"Error in project context for {project_id}: {e}")
        raise