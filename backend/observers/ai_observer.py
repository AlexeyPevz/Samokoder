"""
AI Observer
Наблюдатель за событиями AI
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta

from backend.events.base_event import BaseEvent, AIRequestEvent
from backend.bus.event_bus import EventHandler

logger = logging.getLogger(__name__)

class AIObserver(EventHandler):
    """Наблюдатель за событиями AI"""
    
    def __init__(self):
        self._usage_stats: Dict[str, Dict[str, Any]] = {}
        self._recent_requests: List[AIRequestEvent] = []
        self._cost_threshold = 100.0  # Порог стоимости для алертов
    
    def can_handle(self, event_type: str) -> bool:
        """Проверить, может ли обработать событие"""
        return event_type == "ai_request"
    
    async def handle(self, event: BaseEvent) -> None:
        """Обработать событие AI"""
        if isinstance(event, AIRequestEvent):
            await self._handle_ai_request(event)
    
    async def _handle_ai_request(self, event: AIRequestEvent):
        """Обработать событие запроса к AI"""
        user_id = event.user_id
        provider = event.provider
        
        # Обновляем статистику пользователя
        if user_id not in self._usage_stats:
            self._usage_stats[user_id] = {
                "total_requests": 0,
                "total_tokens": 0,
                "total_cost": 0.0,
                "successful_requests": 0,
                "failed_requests": 0,
                "providers": {}
            }
        
        user_stats = self._usage_stats[user_id]
        user_stats["total_requests"] += 1
        user_stats["total_tokens"] += event.tokens_used
        user_stats["total_cost"] += event.cost
        
        if event.success:
            user_stats["successful_requests"] += 1
        else:
            user_stats["failed_requests"] += 1
        
        # Обновляем статистику по провайдерам
        if provider not in user_stats["providers"]:
            user_stats["providers"][provider] = {
                "requests": 0,
                "tokens": 0,
                "cost": 0.0,
                "success_rate": 0.0
            }
        
        provider_stats = user_stats["providers"][provider]
        provider_stats["requests"] += 1
        provider_stats["tokens"] += event.tokens_used
        provider_stats["cost"] += event.cost
        
        # Пересчитываем success rate
        if provider_stats["requests"] > 0:
            provider_stats["success_rate"] = (
                user_stats["successful_requests"] / user_stats["total_requests"]
            )
        
        # Добавляем в список недавних запросов
        self._recent_requests.append(event)
        
        # Очищаем старые запросы (старше 24 часов)
        cutoff_time = datetime.now() - timedelta(hours=24)
        self._recent_requests = [
            req for req in self._recent_requests 
            if req.timestamp > cutoff_time
        ]
        
        logger.info(f"AI request processed: {provider} for user {user_id}")
        
        # Проверяем пороги и отправляем алерты
        await self._check_thresholds(user_id, event)
    
    async def _check_thresholds(self, user_id: str, event: AIRequestEvent):
        """Проверить пороги и отправить алерты"""
        user_stats = self._usage_stats.get(user_id, {})
        total_cost = user_stats.get("total_cost", 0.0)
        
        # Проверяем порог стоимости
        if total_cost > self._cost_threshold:
            logger.warning(f"User {user_id} exceeded cost threshold: ${total_cost:.2f}")
            # Здесь можно отправить уведомление пользователю
        
        # Проверяем частоту запросов
        recent_user_requests = [
            req for req in self._recent_requests 
            if req.user_id == user_id and req.timestamp > datetime.now() - timedelta(hours=1)
        ]
        
        if len(recent_user_requests) > 100:  # Более 100 запросов в час
            logger.warning(f"User {user_id} has high request frequency: {len(recent_user_requests)} requests/hour")
            # Здесь можно применить rate limiting
    
    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Получить статистику пользователя"""
        return self._usage_stats.get(user_id, {
            "total_requests": 0,
            "total_tokens": 0,
            "total_cost": 0.0,
            "successful_requests": 0,
            "failed_requests": 0,
            "providers": {}
        })
    
    def get_provider_stats(self, provider: str) -> Dict[str, Any]:
        """Получить статистику по провайдеру"""
        total_requests = 0
        total_tokens = 0
        total_cost = 0.0
        successful_requests = 0
        
        for user_stats in self._usage_stats.values():
            if provider in user_stats["providers"]:
                provider_stats = user_stats["providers"][provider]
                total_requests += provider_stats["requests"]
                total_tokens += provider_stats["tokens"]
                total_cost += provider_stats["cost"]
                successful_requests += int(provider_stats["requests"] * provider_stats["success_rate"])
        
        return {
            "total_requests": total_requests,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "success_rate": successful_requests / total_requests if total_requests > 0 else 0.0
        }
    
    def get_global_stats(self) -> Dict[str, Any]:
        """Получить глобальную статистику"""
        total_users = len(self._usage_stats)
        total_requests = sum(stats["total_requests"] for stats in self._usage_stats.values())
        total_tokens = sum(stats["total_tokens"] for stats in self._usage_stats.values())
        total_cost = sum(stats["total_cost"] for stats in self._usage_stats.values())
        
        return {
            "total_users": total_users,
            "total_requests": total_requests,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "recent_requests_24h": len(self._recent_requests)
        }