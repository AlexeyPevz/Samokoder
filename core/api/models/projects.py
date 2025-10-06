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
    
    @validator('name')
    def validate_name(cls, v):
        """Валидация названия проекта (P1-2: ENABLED)."""
        if not v or not v.strip():
            raise ValueError('Название проекта не может быть пустым')
        
        # Проверка на потенциально опасные символы для XSS
        dangerous_chars = ['<', '>', '&', '"', "'"]
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f'Название содержит запрещенный символ: {char}')
        
        # Проверка на SQL ключевые слова (defense in depth)
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'truncate']
        name_lower = v.lower()
        for keyword in sql_keywords:
            # Проверяем как отдельное слово
            if keyword in name_lower.split():
                raise ValueError(f'Название содержит запрещенное слово: {keyword}')
        
        return v.strip()
 
class ProjectUpdateRequest(BaseModel):
    """Запрос на обновление проекта."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    
    @validator('name')
    def validate_name(cls, v):
        """Валидация названия проекта при обновлении (P1-2: ENABLED)."""
        if v is not None:
            if not v.strip():
                raise ValueError('Название проекта не может быть пустым')
            
            # Те же проверки безопасности
            dangerous_chars = ['<', '>', '&', '"', "'"]
            for char in dangerous_chars:
                if char in v:
                    raise ValueError(f'Название содержит запрещенный символ: {char}')
            
            return v.strip()
        return v
 
class ProjectListResponse(BaseResponse):
    """Ответ со списком проектов."""
    projects: List[ProjectResponse]
    total: int


class ProjectDetailResponse(BaseResponse):
    """Детальный ответ с проектом."""
    project: ProjectResponse
