"""
Pydantic модели для проектов API.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, validator
from uuid import UUID

from .base import BaseResponse, ProjectBase, ProjectResponse


class ProjectCreateRequest(BaseModel):
    """Запрос на создание проекта."""
    name: str = Field(..., min_length=1, max_length=100, description="Название проекта")
    description: Optional[str] = Field(None, max_length=1000, description="Описание проекта")
    
    # TEMPORARILY DISABLED
    #     @validator('name')
    #     def validate_name(cls, v):
    #         """Валидация названия проекта."""
    #         if not v.strip():
    #             raise ValueError('Название проекта не может быть пустым')
    #         
    #         # Проверка на потенциально опасные символы
    #         dangerous_chars = ['<', '>', '&', '"', "'", '\\', '/']
    #         for char in dangerous_chars:
    #             if char in v:
    #                 raise ValueError(f'Название содержит запрещенный символ: {char}')
    #         
    #         # Проверка на SQL ключевые слова
    #         sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
    #         name_lower = v.lower()
    #         for keyword in sql_keywords:
    #             if keyword in name_lower:
    #                 raise ValueError(f'Название содержит запрещенное слово: {keyword}')
    #         
    #         return v.strip()
    # 
    # 
class ProjectUpdateRequest(BaseModel):
    """Запрос на обновление проекта."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    
    # TEMPORARILY DISABLED
    #     @validator('name')
    #     def validate_name(cls, v):
    #         if v is not None:
    #             if not v.strip():
    #                 raise ValueError('Название проекта не может быть пустым')
    #             return v.strip()
    #         return v
    # 
    # 
class ProjectListResponse(BaseResponse):
    """Ответ со списком проектов."""
    projects: List[ProjectResponse]
    total: int


class ProjectDetailResponse(BaseResponse):
    """Детальный ответ с проектом."""
    project: ProjectResponse
