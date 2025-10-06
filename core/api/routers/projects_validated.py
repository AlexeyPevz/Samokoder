"""
Роутер проектов с валидацией входных данных.

Использует Pydantic модели для:
- Валидации данных
- Защиты от SQL injection
- Типизации
- Документирования API
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import List, Optional

from samokoder.core.db.session import get_db
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User
from samokoder.core.db.models.project import Project
from samokoder.core.api.models import (
    ProjectCreateRequest,
    ProjectUpdateRequest,
    ProjectListResponse,
    ProjectDetailResponse,
    ProjectResponse,
    ErrorResponse
)

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("/", response_model=ProjectListResponse)
async def get_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Номер страницы"),
    limit: int = Query(10, ge=1, le=100, description="Количество проектов на странице")
):
    """
    Получить список проектов пользователя с пагинацией.
    
    - **page**: Номер страницы (начиная с 1)
    - **limit**: Количество проектов на странице (1-100)
    """
    try:
        # Считаем общее количество проектов
        total_query = select(Project).where(Project.user_id == current_user.id)
        total_result = await db.execute(total_query)
        total = len(total_result.scalars().all())
        
        # Получаем проекты с пагинацией
        offset = (page - 1) * limit
        projects_query = (
            select(Project)
            .where(Project.user_id == current_user.id)
            .offset(offset)
            .limit(limit)
        )
        result = await db.execute(projects_query)
        projects = result.scalars().all()
        
        # Преобразуем в response модели
        project_responses = [
            ProjectResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                created_at=p.created_at,
                user_id=p.user_id
            ) for p in projects
        ]
        
        # Вычисляем количество страниц
        pages = (total + limit - 1) // limit
        
        return ProjectListResponse(
            projects=project_responses,
            total=total,
            page=page,
            limit=limit,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении проектов: {str(e)}"
        )


@router.post("/", response_model=ProjectDetailResponse)
async def create_project(
    project_data: ProjectCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Создать новый проект.
    
    Валидация включает:
    - Проверку названия проекта
    - Защиту от SQL injection
    - Ограничение длины полей
    """
    try:
        # Создаем проект
        project = Project(
            name=project_data.name,
            description=project_data.description,
            user_id=current_user.id
        )
        
        db.add(project)
        await db.commit()
        await db.refresh(project)
        
        # Преобразуем в response модель
        project_response = ProjectResponse(
            id=project.id,
            name=project.name,
            description=project.description,
            created_at=project.created_at,
            user_id=project.user_id
        )
        
        return ProjectDetailResponse(project=project_response)
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при создании проекта: {str(e)}"
        )


@router.get("/{project_id}", response_model=ProjectDetailResponse)
async def get_project(
    project_id: str,  # UUID как строка для валидации
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Получить проект по ID.
    
    - **project_id**: UUID проекта
    """
    try:
        # Валидация UUID
        try:
            from uuid import UUID
            project_uuid = UUID(project_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Неверный формат ID проекта"
            )
        
        # Поиск проекта
        query = select(Project).where(
            Project.id == project_uuid,
            Project.user_id == current_user.id
        )
        result = await db.execute(query)
        project = result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=404,
                detail="Проект не найден"
            )
        
        # Преобразуем в response модель
        project_response = ProjectResponse(
            id=project.id,
            name=project.name,
            description=project.description,
            created_at=project.created_at,
            user_id=project.user_id
        )
        
        return ProjectDetailResponse(project=project_response)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении проекта: {str(e)}"
        )


@router.put("/{project_id}", response_model=ProjectDetailResponse)
async def update_project(
    project_id: str,
    project_data: ProjectUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Обновить проект.
    
    - **project_id**: UUID проекта
    - **project_data**: Данные для обновления
    """
    try:
        # Валидация UUID
        try:
            from uuid import UUID
            project_uuid = UUID(project_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Неверный формат ID проекта"
            )
        
        # Поиск проекта
        query = select(Project).where(
            Project.id == project_uuid,
            Project.user_id == current_user.id
        )
        result = await db.execute(query)
        project = result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=404,
                detail="Проект не найден"
            )
        
        # Обновление полей
        if project_data.name is not None:
            project.name = project_data.name
        if project_data.description is not None:
            project.description = project_data.description
        
        await db.commit()
        await db.refresh(project)
        
        # Преобразуем в response модель
        project_response = ProjectResponse(
            id=project.id,
            name=project.name,
            description=project.description,
            created_at=project.created_at,
            user_id=project.user_id
        )
        
        return ProjectDetailResponse(project=project_response)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при обновлении проекта: {str(e)}"
        )


@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Удалить проект.
    
    - **project_id**: UUID проекта
    """
    try:
        # Валидация UUID
        try:
            from uuid import UUID
            project_uuid = UUID(project_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Неверный формат ID проекта"
            )
        
        # Поиск и удаление проекта
        query = select(Project).where(
            Project.id == project_uuid,
            Project.user_id == current_user.id
        )
        result = await db.execute(query)
        project = result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=404,
                detail="Проект не найден"
            )
        
        await db.delete(project)
        await db.commit()
        
        return {"message": "Проект успешно удален"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при удалении проекта: {str(e)}"
        )
