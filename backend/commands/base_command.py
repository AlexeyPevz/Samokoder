"""
Base Command
Базовые классы для команд
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional, TypeVar, Generic
from uuid import uuid4
from dataclasses import dataclass

T = TypeVar('T')

@dataclass
class BaseCommand(ABC, Generic[T]):
    """Базовый класс для команд"""
    command_id: str
    command_type: str
    timestamp: datetime
    user_id: Optional[str] = None
    project_id: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    @abstractmethod
    def execute(self) -> T:
        """Выполнить команду"""
        pass
    
    @abstractmethod
    def validate(self) -> bool:
        """Проверить валидность команды"""
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать команду в словарь"""
        return {
            "command_id": self.command_id,
            "command_type": self.command_type,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "project_id": self.project_id,
            "metadata": self.metadata
        }
    
    @classmethod
    def create_command_id(cls) -> str:
        """Создать уникальный ID команды"""
        return str(uuid4())
    
    @classmethod
    def get_timestamp(cls) -> datetime:
        """Получить текущее время"""
        return datetime.now()

@dataclass
class CreateProjectCommand(BaseCommand[bool]):
    """Команда создания проекта"""
    name: str
    description: str
    workspace_path: str
    
    def __post_init__(self):
        super().__post_init__()
        self.command_type = "create_project"
    
    def validate(self) -> bool:
        """Проверить валидность команды"""
        if not self.name or not self.name.strip():
            return False
        if not self.user_id:
            return False
        return True
    
    def execute(self) -> bool:
        """Выполнить команду создания проекта"""
        # Здесь будет логика создания проекта
        # Пока возвращаем True для демонстрации
        return True

@dataclass
class DeleteProjectCommand(BaseCommand[bool]):
    """Команда удаления проекта"""
    project_name: str
    
    def __post_init__(self):
        super().__post_init__()
        self.command_type = "delete_project"
    
    def validate(self) -> bool:
        """Проверить валидность команды"""
        if not self.project_id:
            return False
        if not self.user_id:
            return False
        return True
    
    def execute(self) -> bool:
        """Выполнить команду удаления проекта"""
        # Здесь будет логика удаления проекта
        # Пока возвращаем True для демонстрации
        return True

@dataclass
class SendAIRequestCommand(BaseCommand[Dict[str, Any]]):
    """Команда отправки запроса к AI"""
    messages: list[Dict[str, str]]
    model: str
    provider: str
    max_tokens: int = 4096
    temperature: float = 0.7
    
    def __post_init__(self):
        super().__post_init__()
        self.command_type = "send_ai_request"
    
    def validate(self) -> bool:
        """Проверить валидность команды"""
        if not self.messages:
            return False
        if not self.model or not self.provider:
            return False
        if not self.user_id:
            return False
        return True
    
    def execute(self) -> Dict[str, Any]:
        """Выполнить команду отправки запроса к AI"""
        # Здесь будет логика отправки запроса к AI
        # Пока возвращаем заглушку для демонстрации
        return {
            "success": True,
            "content": "AI response placeholder",
            "tokens_used": 0,
            "cost": 0.0
        }