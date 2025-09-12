"""
Улучшенная система мониторинга с детальными метриками
Оркестратор для всех компонентов мониторинга
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional

from .system_metrics import SystemMetricsCollector
from .application_metrics import ApplicationMetricsCollector
from .request_tracker import RequestTracker

logger = logging.getLogger(__name__)

class EnhancedMonitoring:
    """Улучшенная система мониторинга"""
    
    def __init__(self):
        self.system_metrics = SystemMetricsCollector()
        self.app_metrics = ApplicationMetricsCollector()
        self.request_tracker = RequestTracker()
        self._running = False
        self._tasks: List[asyncio.Task] = []
    
    async def start(self):
        """Запустить мониторинг"""
        if self._running:
            logger.warning("Enhanced monitoring already running")
            return
        
        self._running = True
        logger.info("Starting enhanced monitoring system")
        
        # Запускаем фоновые задачи
        self._tasks = [
            asyncio.create_task(self._system_metrics_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
        logger.info("Enhanced monitoring system started")
    
    async def stop(self):
        """Остановить мониторинг"""
        if not self._running:
            return
        
        self._running = False
        logger.info("Stopping enhanced monitoring system")
        
        # Отменяем все задачи
        for task in self._tasks:
            task.cancel()
        
        # Ждем завершения
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        
        logger.info("Enhanced monitoring system stopped")
    
    async def _system_metrics_loop(self):
        """Цикл сбора системных метрик"""
        while self._running:
            try:
                await self.system_metrics.collect_metrics()
                await asyncio.sleep(30)  # Собираем каждые 30 секунд
            except Exception as e:
                logger.error(f"Error in system metrics loop: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_loop(self):
        """Цикл очистки старых данных"""
        while self._running:
            try:
                # Очищаем старые запросы
                self.request_tracker.cleanup_old_requests(max_age_seconds=300)
                await asyncio.sleep(300)  # Очищаем каждые 5 минут
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(300)
    
    # Системные метрики
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Получить системные метрики"""
        metrics = await self.system_metrics.collect_metrics()
        return {
            "cpu_percent": metrics.cpu_percent,
            "memory_percent": metrics.memory_percent,
            "memory_used_mb": metrics.memory_used_mb,
            "memory_available_mb": metrics.memory_available_mb,
            "disk_usage_percent": metrics.disk_usage_percent,
            "disk_free_gb": metrics.disk_free_gb,
            "load_average": metrics.load_average,
            "uptime_seconds": metrics.uptime_seconds,
            "process_count": metrics.process_count,
            "network_connections": metrics.network_connections
        }
    
    # Метрики приложения
    def record_request(self, response_time: float, success: bool = True):
        """Записать запрос"""
        self.app_metrics.record_request(response_time, success)
    
    def set_active_connections(self, count: int):
        """Установить количество активных соединений"""
        self.app_metrics.set_active_connections(count)
    
    def get_application_metrics(self) -> Dict[str, Any]:
        """Получить метрики приложения"""
        return self.app_metrics.get_metrics_summary()
    
    def reset_application_metrics(self):
        """Сбросить метрики приложения"""
        self.app_metrics.reset_metrics()
    
    # Трекер запросов
    def start_request(self, request) -> str:
        """Начать отслеживание запроса"""
        return self.request_tracker.start_request(request)
    
    def finish_request(self, request_id: str, response, success: bool = True, 
                      error: Optional[Exception] = None):
        """Завершить отслеживание запроса"""
        self.request_tracker.finish_request(request_id, response, success, error)
    
    def get_active_requests(self) -> Dict[str, Dict[str, Any]]:
        """Получить активные запросы"""
        return self.request_tracker.get_active_requests()
    
    def get_request_summary(self) -> Dict[str, Any]:
        """Получить сводку запросов"""
        return self.request_tracker.get_request_summary()
    
    # Общее состояние
    def get_comprehensive_metrics(self) -> Dict[str, Any]:
        """Получить все метрики"""
        return {
            "system": self.get_system_metrics(),
            "application": self.get_application_metrics(),
            "requests": self.get_request_summary(),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Получить статус здоровья"""
        try:
            app_metrics = self.get_application_metrics()
            
            # Проверяем критические метрики
            error_rate = app_metrics.get("error_rate_percent", 0)
            avg_response_time = app_metrics.get("average_response_time_ms", 0)
            
            is_healthy = (
                error_rate < 5.0 and  # Error rate < 5%
                avg_response_time < 5000.0  # Response time < 5s
            )
            
            return {
                "healthy": is_healthy,
                "error_rate_percent": error_rate,
                "average_response_time_ms": avg_response_time,
                "active_requests": len(self.get_active_requests()),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error checking health status: {e}")
            return {
                "healthy": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def is_healthy(self) -> bool:
        """Проверить здоровье системы"""
        health = self.get_health_status()
        return health.get("healthy", False)

# Глобальный экземпляр для обратной совместимости
enhanced_monitoring = EnhancedMonitoring()