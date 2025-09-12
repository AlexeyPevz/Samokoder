"""
Project management endpoints
Теперь использует модульную структуру
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status
from backend.models.requests import ProjectCreateRequest, ProjectUpdateRequest
from backend.models.responses import ProjectResponse, ProjectListResponse, ProjectCreateResponse
from backend.auth.dependencies import get_current_user
from backend.middleware.secure_rate_limiter import api_rate_limit
from backend.api.projects.project_handlers import ProjectHandlers
import logging
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter()

# Создаем экземпляр обработчиков
project_handlers = ProjectHandlers()

@router.post("/", response_model=ProjectCreateResponse)
async def create_project(
    project_data: ProjectCreateRequest,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Создать новый проект"""
    return await project_handlers.create_project(project_data, current_user["id"])

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить проект по ID"""
    return await project_handlers.get_project(project_id, current_user["id"])

@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    update_data: ProjectUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    """Обновить проект"""
    return await project_handlers.update_project(project_id, update_data, current_user["id"])

@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Удалить проект"""
    return await project_handlers.delete_project(project_id, current_user["id"])

@router.get("/", response_model=ProjectListResponse)
async def list_projects(
    current_user: dict = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None)
):
    """Получить список проектов пользователя"""
    try:
        # Здесь должна быть логика получения списка проектов
        # Пока возвращаем заглушку
        return ProjectListResponse(
            projects=[],
            total=0,
            skip=skip,
            limit=limit
        )
        
    except Exception as e:
        logger.error(f"Failed to list projects: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list projects"
        )