"""
Project Builder
Строитель для создания проектов
"""

import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from uuid import uuid4

from backend.models.requests import ProjectCreateRequest
from backend.models.responses import ProjectCreateResponse

logger = logging.getLogger(__name__)

class ProjectBuilder:
    """Строитель для создания проектов"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Сбросить состояние строителя"""
        self._project_id = None
        self._user_id = None
        self._name = None
        self._description = None
        self._workspace_path = None
        self._status = "active"
        self._is_active = True
        self._metadata = {}
        self._files = []
        self._dependencies = []
        return self
    
    def set_basic_info(self, user_id: str, name: str, description: str = "") -> 'ProjectBuilder':
        """Установить основную информацию о проекте"""
        self._user_id = user_id
        self._name = name
        self._description = description
        return self
    
    def set_project_id(self, project_id: str) -> 'ProjectBuilder':
        """Установить ID проекта"""
        self._project_id = project_id
        return self
    
    def generate_project_id(self) -> 'ProjectBuilder':
        """Сгенерировать новый ID проекта"""
        self._project_id = str(uuid4())
        return self
    
    def set_workspace_path(self, workspace_path: str) -> 'ProjectBuilder':
        """Установить путь к рабочей директории"""
        self._workspace_path = workspace_path
        return self
    
    def generate_workspace_path(self) -> 'ProjectBuilder':
        """Сгенерировать путь к рабочей директории"""
        if not self._user_id or not self._project_id:
            raise ValueError("User ID and Project ID must be set before generating workspace path")
        
        self._workspace_path = f"workspaces/{self._user_id}/{self._project_id}"
        return self
    
    def set_status(self, status: str) -> 'ProjectBuilder':
        """Установить статус проекта"""
        self._status = status
        return self
    
    def set_active(self, is_active: bool) -> 'ProjectBuilder':
        """Установить активность проекта"""
        self._is_active = is_active
        return self
    
    def add_metadata(self, key: str, value: Any) -> 'ProjectBuilder':
        """Добавить метаданные проекта"""
        self._metadata[key] = value
        return self
    
    def add_file(self, file_path: str, content: str = "") -> 'ProjectBuilder':
        """Добавить файл в проект"""
        self._files.append({
            "path": file_path,
            "content": content
        })
        return self
    
    def add_dependency(self, dependency: str) -> 'ProjectBuilder':
        """Добавить зависимость проекта"""
        self._dependencies.append(dependency)
        return self
    
    def create_workspace_directory(self) -> 'ProjectBuilder':
        """Создать рабочую директорию проекта"""
        if not self._workspace_path:
            raise ValueError("Workspace path must be set before creating directory")
        
        workspace_dir = Path(self._workspace_path)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Создаем базовые файлы
        if self._files:
            for file_info in self._files:
                file_path = workspace_dir / file_info["path"]
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(file_info["content"], encoding='utf-8')
        
        logger.info(f"Created workspace directory: {self._workspace_path}")
        return self
    
    def build_request(self) -> ProjectCreateRequest:
        """Построить запрос создания проекта"""
        if not self._name:
            raise ValueError("Project name is required")
        
        return ProjectCreateRequest(
            name=self._name,
            description=self._description or ""
        )
    
    def build_response(self, success: bool = True, message: str = "") -> ProjectCreateResponse:
        """Построить ответ создания проекта"""
        if not self._project_id:
            raise ValueError("Project ID is required")
        
        return ProjectCreateResponse(
            success=success,
            message=message or ("Проект создан успешно" if success else "Ошибка создания проекта"),
            project_id=self._project_id,
            workspace_path=self._workspace_path or ""
        )
    
    def build_database_data(self) -> Dict[str, Any]:
        """Построить данные для сохранения в базу"""
        if not self._user_id or not self._name:
            raise ValueError("User ID and name are required")
        
        return {
            "id": self._project_id or str(uuid4()),
            "name": self._name,
            "description": self._description or "",
            "user_id": self._user_id,
            "status": self._status,
            "is_active": self._is_active,
            "metadata": self._metadata,
            "dependencies": self._dependencies
        }
    
    def validate(self) -> bool:
        """Проверить валидность данных проекта"""
        if not self._user_id:
            logger.error("User ID is required")
            return False
        
        if not self._name:
            logger.error("Project name is required")
            return False
        
        if not self._project_id:
            logger.error("Project ID is required")
            return False
        
        return True

def get_project_builder() -> ProjectBuilder:
    """Получить билдер проектов (использует DI контейнер)"""
    from backend.core.dependency_injection import get_container
    container = get_container()
    return container.get(ProjectBuilder)