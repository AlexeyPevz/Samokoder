"""
Обработчики для проектов
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import HTTPException, status

from backend.models.requests import ProjectCreateRequest, ProjectUpdateRequest
from backend.models.responses import ProjectResponse, ProjectCreateResponse
from backend.utils.uuid_manager import generate_unique_uuid
from backend.security.simple_input_validator import validate_project_name

logger = logging.getLogger(__name__)

class ProjectHandlers:
    """Обработчики для операций с проектами"""
    
    def __init__(self):
        self.logger = logger
    
    async def create_project(self, project_data: ProjectCreateRequest, user_id: str) -> ProjectCreateResponse:
        """Создать новый проект"""
        try:
            # Валидация данных
            if not validate_project_name(project_data.name):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid project name"
                )
            
            # Генерируем уникальный ID
            project_id = generate_unique_uuid()
            
            # Создаем рабочую директорию
            await self._create_workspace_directory(project_id, user_id)
            
            # Сохраняем проект в базе данных
            await self._save_project_to_database(project_id, project_data, user_id)
            
            return ProjectCreateResponse(
                success=True,
                message="Проект создан, готов к работе",
                project_id=project_id,
                workspace_path=f"workspaces/{user_id}/{project_id}"
            )
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to create project: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create project"
            )
    
    async def get_project(self, project_id: str, user_id: str) -> ProjectResponse:
        """Получить проект по ID"""
        try:
            # Получаем проект из базы данных
            project_data = await self._get_project_from_database(project_id, user_id)
            
            if not project_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found"
                )
            
            return ProjectResponse(**project_data)
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get project {project_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get project"
            )
    
    async def update_project(self, project_id: str, update_data: ProjectUpdateRequest, user_id: str) -> ProjectResponse:
        """Обновить проект"""
        try:
            # Проверяем существование проекта
            existing_project = await self._get_project_from_database(project_id, user_id)
            if not existing_project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found"
                )
            
            # Валидация данных
            if update_data.name and not validate_project_name(update_data.name):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid project name"
                )
            
            # Обновляем проект в базе данных
            updated_project = await self._update_project_in_database(project_id, update_data, user_id)
            
            return ProjectResponse(**updated_project)
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to update project {project_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update project"
            )
    
    async def delete_project(self, project_id: str, user_id: str) -> Dict[str, Any]:
        """Удалить проект"""
        try:
            # Проверяем существование проекта
            existing_project = await self._get_project_from_database(project_id, user_id)
            if not existing_project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found"
                )
            
            # Удаляем проект из базы данных
            await self._delete_project_from_database(project_id, user_id)
            
            # Удаляем рабочую директорию
            await self._delete_workspace_directory(project_id, user_id)
            
            return {
                "success": True,
                "message": "Project deleted successfully"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to delete project {project_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete project"
            )
    
    async def _create_workspace_directory(self, project_id: str, user_id: str):
        """Создать рабочую директорию проекта"""
        try:
            workspace_path = Path(f"workspaces/{user_id}/{project_id}")
            workspace_path.mkdir(parents=True, exist_ok=True)
            
            self.logger.info(f"Created workspace directory: {workspace_path}")
            
        except PermissionError as e:
            self.logger.error(f"Permission denied creating workspace directory: {e}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied creating workspace directory"
            )
        except OSError as e:
            self.logger.error(f"OS error creating workspace directory: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create workspace directory"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error creating workspace directory: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create workspace directory"
            )
    
    async def _save_project_to_database(self, project_id: str, project_data: ProjectCreateRequest, user_id: str):
        """Сохранить проект в базе данных"""
        # Здесь должна быть логика сохранения в Supabase
        # Пока заглушка
        pass
    
    async def _get_project_from_database(self, project_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Получить проект из базы данных"""
        # Здесь должна быть логика получения из Supabase
        # Пока заглушка
        return None
    
    async def _update_project_in_database(self, project_id: str, update_data: ProjectUpdateRequest, user_id: str) -> Dict[str, Any]:
        """Обновить проект в базе данных"""
        # Здесь должна быть логика обновления в Supabase
        # Пока заглушка
        return {}
    
    async def _delete_project_from_database(self, project_id: str, user_id: str):
        """Удалить проект из базы данных"""
        # Здесь должна быть логика удаления из Supabase
        # Пока заглушка
        pass
    
    async def _delete_workspace_directory(self, project_id: str, user_id: str):
        """Удалить рабочую директорию проекта"""
        try:
            workspace_path = Path(f"workspaces/{user_id}/{project_id}")
            if workspace_path.exists():
                import shutil
                shutil.rmtree(workspace_path)
                self.logger.info(f"Deleted workspace directory: {workspace_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to delete workspace directory: {e}")
            # Не поднимаем исключение, так как проект уже удален из БД