"""
AI Usage Tracker
Трекер использования AI сервисов
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass

from .models import AIProvider, AIResponse

logger = logging.getLogger(__name__)

@dataclass
class UsageStats:
    """Статистика использования"""
    total_requests: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0
    success_rate: float = 0.0
    avg_response_time: float = 0.0
    last_used: Optional[datetime] = None

class AIUsageTracker:
    """Трекер использования AI сервисов"""
    
    def __init__(self):
        self._usage: Dict[str, Dict[AIProvider, UsageStats]] = {}
        self._requests: List[AIResponse] = []
    
    def track_request(self, user_id: str, response: AIResponse):
        """Отследить запрос"""
        if user_id not in self._usage:
            self._usage[user_id] = {}
        
        if response.provider not in self._usage[user_id]:
            self._usage[user_id][response.provider] = UsageStats()
        
        stats = self._usage[user_id][response.provider]
        self._requests.append(response)
        
        # Обновляем статистику
        stats.total_requests += 1
        stats.total_tokens += response.tokens_used
        stats.total_cost += response.cost_usd
        stats.last_used = datetime.now()
        
        # Пересчитываем средние значения
        user_requests = [r for r in self._requests if r.provider == response.provider]
        successful_requests = [r for r in user_requests if r.success]
        
        stats.success_rate = len(successful_requests) / len(user_requests) if user_requests else 0
        stats.avg_response_time = sum(r.response_time for r in user_requests) / len(user_requests) if user_requests else 0
        
        logger.debug(f"Tracked AI request for user {user_id}: {response.provider}")
    
    def get_user_stats(self, user_id: str) -> Dict[AIProvider, UsageStats]:
        """Получить статистику пользователя"""
        return self._usage.get(user_id, {})
    
    def get_provider_stats(self, provider: AIProvider) -> UsageStats:
        """Получить статистику по провайдеру"""
        total_stats = UsageStats()
        
        for user_stats in self._usage.values():
            if provider in user_stats:
                stats = user_stats[provider]
                total_stats.total_requests += stats.total_requests
                total_stats.total_tokens += stats.total_tokens
                total_stats.total_cost += stats.total_cost
        
        # Пересчитываем средние значения
        provider_requests = [r for r in self._requests if r.provider == provider]
        if provider_requests:
            successful_requests = [r for r in provider_requests if r.success]
            total_stats.success_rate = len(successful_requests) / len(provider_requests)
            total_stats.avg_response_time = sum(r.response_time for r in provider_requests) / len(provider_requests)
        
        return total_stats
    
    def get_recent_requests(self, hours: int = 24) -> List[AIResponse]:
        """Получить недавние запросы"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [r for r in self._requests if r.response_time >= cutoff.timestamp()]
    
    def cleanup_old_requests(self, days: int = 30):
        """Очистить старые запросы"""
        cutoff = datetime.now() - timedelta(days=days)
        self._requests = [r for r in self._requests if r.response_time >= cutoff.timestamp()]
        logger.info(f"Cleaned up requests older than {days} days")

# Глобальный экземпляр трекера
usage_tracker = AIUsageTracker()