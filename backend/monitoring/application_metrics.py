"""
Метрики приложения
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
from dataclasses import dataclass, field
from collections import deque

logger = logging.getLogger(__name__)

@dataclass
class ApplicationMetrics:
    """Метрики приложения"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    active_connections: int = 0
    average_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    error_rate: float = 0.0
    requests_per_second: float = 0.0

class ApplicationMetricsCollector:
    """Сборщик метрик приложения"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.response_times = deque(maxlen=window_size)
        self.request_times = deque(maxlen=window_size)
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.active_connections = 0
        self._last_reset = datetime.now()
    
    def record_request(self, response_time: float, success: bool = True):
        """Записать запрос"""
        self.total_requests += 1
        self.response_times.append(response_time)
        self.request_times.append(time.time())
        
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
    
    def set_active_connections(self, count: int):
        """Установить количество активных соединений"""
        self.active_connections = count
    
    def calculate_metrics(self) -> ApplicationMetrics:
        """Вычислить метрики"""
        if not self.response_times:
            return ApplicationMetrics()
        
        # Сортируем времена ответа для перцентилей
        sorted_times = sorted(self.response_times)
        count = len(sorted_times)
        
        # Среднее время ответа
        average_response_time = sum(sorted_times) / count
        
        # P95 и P99
        p95_index = int(count * 0.95)
        p99_index = int(count * 0.99)
        p95_response_time = sorted_times[p95_index] if p95_index < count else sorted_times[-1]
        p99_response_time = sorted_times[p99_index] if p99_index < count else sorted_times[-1]
        
        # Error rate
        error_rate = (self.failed_requests / self.total_requests) * 100 if self.total_requests > 0 else 0
        
        # Requests per second
        now = time.time()
        recent_requests = [t for t in self.request_times if now - t <= 60]  # Последняя минута
        requests_per_second = len(recent_requests) / 60.0
        
        return ApplicationMetrics(
            total_requests=self.total_requests,
            successful_requests=self.successful_requests,
            failed_requests=self.failed_requests,
            active_connections=self.active_connections,
            average_response_time=average_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_rate=error_rate,
            requests_per_second=requests_per_second
        )
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Получить сводку метрик"""
        metrics = self.calculate_metrics()
        return {
            "total_requests": metrics.total_requests,
            "successful_requests": metrics.successful_requests,
            "failed_requests": metrics.failed_requests,
            "active_connections": metrics.active_connections,
            "average_response_time_ms": metrics.average_response_time * 1000,
            "p95_response_time_ms": metrics.p95_response_time * 1000,
            "p99_response_time_ms": metrics.p99_response_time * 1000,
            "error_rate_percent": metrics.error_rate,
            "requests_per_second": metrics.requests_per_second,
            "window_size": self.window_size,
            "last_reset": self._last_reset.isoformat()
        }
    
    def reset_metrics(self):
        """Сбросить метрики"""
        self.response_times.clear()
        self.request_times.clear()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.active_connections = 0
        self._last_reset = datetime.now()
        logger.info("Application metrics reset")