"""
Продвинутая система мониторинга и логирования
Оркестратор для всех компонентов мониторинга
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from .metrics import MetricsCollector
from .alerts import AlertManager, AlertRule
from .tracing import TraceManager
from .dashboard import DashboardManager

logger = logging.getLogger(__name__)

class AdvancedMonitoring:
    """Продвинутая система мониторинга"""
    
    def __init__(self):
        self.metrics = MetricsCollector()
        self.alerts = AlertManager()
        self.tracing = TraceManager()
        self.dashboard = DashboardManager()
        self._running = False
        self._tasks: List[asyncio.Task] = []
    
    async def start(self):
        """Запустить мониторинг"""
        if self._running:
            logger.warning("Monitoring already running")
            return
        
        self._running = True
        logger.info("Starting advanced monitoring system")
        
        # Запускаем фоновые задачи
        self._tasks = [
            asyncio.create_task(self._metrics_collection_loop()),
            asyncio.create_task(self._alerts_check_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
        logger.info("Advanced monitoring system started")
    
    async def stop(self):
        """Остановить мониторинг"""
        if not self._running:
            return
        
        self._running = False
        logger.info("Stopping advanced monitoring system")
        
        # Отменяем все задачи
        for task in self._tasks:
            task.cancel()
        
        # Ждем завершения
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        
        logger.info("Advanced monitoring system stopped")
    
    async def _metrics_collection_loop(self):
        """Цикл сбора метрик"""
        while self._running:
            try:
                await self.metrics.collect_system_metrics()
                await asyncio.sleep(30)  # Собираем каждые 30 секунд
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(60)
    
    async def _alerts_check_loop(self):
        """Цикл проверки алертов"""
        while self._running:
            try:
                metrics_data = self.metrics.get_metrics_summary()
                await self.alerts.check_alerts(metrics_data)
                await asyncio.sleep(60)  # Проверяем каждую минуту
            except Exception as e:
                logger.error(f"Error in alerts check loop: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_loop(self):
        """Цикл очистки старых данных"""
        while self._running:
            try:
                # Очищаем старые алерты
                self.alerts.clear_resolved_alerts(older_than_hours=24)
                await asyncio.sleep(3600)  # Очищаем каждый час
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(3600)
    
    # Метрики
    def increment_counter(self, name: str, labels: Dict[str, str] = None):
        """Увеличить счетчик"""
        self.metrics.increment_counter(name, labels)
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Установить значение gauge"""
        self.metrics.set_gauge(name, value, labels)
    
    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Наблюдать гистограмму"""
        self.metrics.observe_histogram(name, value, labels)
    
    def add_custom_metric(self, name: str, value: float, metric_type: str, 
                         labels: Dict[str, str] = None):
        """Добавить кастомную метрику"""
        self.metrics.add_custom_metric(name, value, metric_type, labels)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Получить сводку метрик"""
        return self.metrics.get_metrics_summary()
    
    # Алерты
    def add_alert_rule(self, rule: AlertRule):
        """Добавить правило алерта"""
        self.alerts.add_rule(rule)
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Получить активные алерты"""
        return [alert.__dict__ for alert in self.alerts.get_active_alerts()]
    
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Получить историю алертов"""
        return [alert.__dict__ for alert in self.alerts.get_alert_history(limit)]
    
    # Трейсинг
    def start_trace(self, operation_name: str, service_name: str = "samokoder") -> str:
        """Начать новый трейс"""
        return self.tracing.start_trace(operation_name, service_name)
    
    def start_span(self, trace_id: str, operation_name: str, 
                   parent_span_id: Optional[str] = None) -> str:
        """Начать новый спан"""
        return self.tracing.start_span(trace_id, operation_name, parent_span_id)
    
    def finish_span(self, span_id: str, status: str = "completed", 
                   error: Optional[Exception] = None):
        """Завершить спан"""
        self.tracing.finish_span(span_id, status, error)
    
    def finish_trace(self, trace_id: str):
        """Завершить трейс"""
        self.tracing.finish_trace(trace_id)
    
    def add_span_tag(self, span_id: str, key: str, value: Any):
        """Добавить тег к спану"""
        self.tracing.add_span_tag(span_id, key, value)
    
    def add_span_log(self, span_id: str, message: str, level: str = "info", **kwargs):
        """Добавить лог к спану"""
        self.tracing.add_span_log(span_id, message, level, **kwargs)
    
    def get_trace_statistics(self) -> Dict[str, Any]:
        """Получить статистику трейсов"""
        return self.tracing.get_trace_statistics()
    
    # Дашборды
    async def get_dashboard_data(self, name: str) -> Dict[str, Any]:
        """Получить данные дашборда"""
        metrics_data = self.get_metrics_summary()
        return await self.dashboard.get_dashboard_data(name, metrics_data)
    
    def get_available_dashboards(self) -> List[str]:
        """Получить доступные дашборды"""
        return self.dashboard.list_dashboards()
    
    # Общее состояние
    def get_system_status(self) -> Dict[str, Any]:
        """Получить общий статус системы"""
        return {
            "running": self._running,
            "metrics": self.get_metrics_summary(),
            "active_alerts": len(self.get_active_alerts()),
            "tracing": self.get_trace_statistics(),
            "dashboards": self.dashboard.get_dashboard_summary(),
            "timestamp": datetime.now().isoformat()
        }
    
    def is_healthy(self) -> bool:
        """Проверить здоровье системы мониторинга"""
        try:
            # Проверяем, что нет критических алертов
            active_alerts = self.get_active_alerts()
            critical_alerts = [alert for alert in active_alerts if alert.get("severity") == "critical"]
            
            # Проверяем, что система работает
            return self._running and len(critical_alerts) == 0
        except Exception as e:
            logger.error(f"Error checking system health: {e}")
            return False

# Глобальный экземпляр для обратной совместимости
monitoring = AdvancedMonitoring()