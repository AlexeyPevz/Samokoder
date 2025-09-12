"""
Base Event
Базовые классы для событий
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional
from uuid import uuid4
from dataclasses import dataclass

@dataclass
class BaseEvent(ABC):
    """Базовый класс для событий"""
    event_id: str
    event_type: str
    timestamp: datetime
    user_id: Optional[str] = None
    project_id: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать событие в словарь"""
        pass
    
    @classmethod
    def create_event_id(cls) -> str:
        """Создать уникальный ID события"""
        return str(uuid4())
    
    @classmethod
    def get_timestamp(cls) -> datetime:
        """Получить текущее время"""
        return datetime.now()

@dataclass
class ProjectCreatedEvent(BaseEvent):
    """Событие создания проекта"""
    project_name: str
    workspace_path: str
    
    def __post_init__(self):
        super().__post_init__()
        self.event_type = "project_created"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "workspace_path": self.workspace_path,
            "metadata": self.metadata
        }

@dataclass
class ProjectDeletedEvent(BaseEvent):
    """Событие удаления проекта"""
    project_name: str
    
    def __post_init__(self):
        super().__post_init__()
        self.event_type = "project_deleted"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "metadata": self.metadata
        }

@dataclass
class AIRequestEvent(BaseEvent):
    """Событие запроса к AI"""
    provider: str
    model: str
    tokens_used: int
    cost: float
    success: bool
    
    def __post_init__(self):
        super().__post_init__()
        self.event_type = "ai_request"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "project_id": self.project_id,
            "provider": self.provider,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "cost": self.cost,
            "success": self.success,
            "metadata": self.metadata
        }

@dataclass
class UserLoginEvent(BaseEvent):
    """Событие входа пользователя"""
    login_method: str
    ip_address: Optional[str] = None
    
    def __post_init__(self):
        super().__post_init__()
        self.event_type = "user_login"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "login_method": self.login_method,
            "ip_address": self.ip_address,
            "metadata": self.metadata
        }