"""
Project Observer
Наблюдатель за событиями проектов
"""

import logging
from typing import Dict, Any

from backend.events.base_event import BaseEvent, ProjectCreatedEvent, ProjectDeletedEvent
from backend.bus.event_bus import EventHandler

logger = logging.getLogger(__name__)

class ProjectObserver(EventHandler):
    """Наблюдатель за событиями проектов"""
    
    def __init__(self):
        self._project_stats: Dict[str, Any] = {}
    
    def can_handle(self, event_type: str) -> bool:
        """Проверить, может ли обработать событие"""
        return event_type in ["project_created", "project_deleted"]
    
    async def handle(self, event: BaseEvent) -> None:
        """Обработать событие проекта"""
        if isinstance(event, ProjectCreatedEvent):
            await self._handle_project_created(event)
        elif isinstance(event, ProjectDeletedEvent):
            await self._handle_project_deleted(event)
    
    async def _handle_project_created(self, event: ProjectCreatedEvent):
        """Обработать событие создания проекта"""
        user_id = event.user_id
        
        if user_id not in self._project_stats:
            self._project_stats[user_id] = {
                "total_projects": 0,
                "active_projects": 0,
                "deleted_projects": 0
            }
        
        self._project_stats[user_id]["total_projects"] += 1
        self._project_stats[user_id]["active_projects"] += 1
        
        logger.info(f"Project created: {event.project_name} for user {user_id}")
        
        # Здесь можно добавить дополнительную логику:
        # - Отправка уведомлений
        # - Обновление метрик
        # - Создание резервных копий
        # - Инициализация дополнительных сервисов
    
    async def _handle_project_deleted(self, event: ProjectDeletedEvent):
        """Обработать событие удаления проекта"""
        user_id = event.user_id
        
        if user_id in self._project_stats:
            self._project_stats[user_id]["active_projects"] = max(0, self._project_stats[user_id]["active_projects"] - 1)
            self._project_stats[user_id]["deleted_projects"] += 1
        
        logger.info(f"Project deleted: {event.project_name} for user {user_id}")
        
        # Здесь можно добавить дополнительную логику:
        # - Очистка ресурсов
        # - Архивирование данных
        # - Уведомление команды
    
    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Получить статистику пользователя"""
        return self._project_stats.get(user_id, {
            "total_projects": 0,
            "active_projects": 0,
            "deleted_projects": 0
        })
    
    def get_global_stats(self) -> Dict[str, Any]:
        """Получить глобальную статистику"""
        total_users = len(self._project_stats)
        total_projects = sum(stats["total_projects"] for stats in self._project_stats.values())
        active_projects = sum(stats["active_projects"] for stats in self._project_stats.values())
        deleted_projects = sum(stats["deleted_projects"] for stats in self._project_stats.values())
        
        return {
            "total_users": total_users,
            "total_projects": total_projects,
            "active_projects": active_projects,
            "deleted_projects": deleted_projects
        }