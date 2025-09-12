"""
Адаптер для мониторинга
Уменьшает связность между компонентами
"""

import logging
from typing import Dict, Any, List, Optional
from backend.interfaces.monitoring import IMonitoringService, IAlertService, ITracingService

logger = logging.getLogger(__name__)

class MonitoringAdapter:
    """Адаптер для мониторинга"""
    
    def __init__(self, monitoring_service: IMonitoringService):
        self.monitoring_service = monitoring_service
    
    async def start_monitoring(self):
        """Запустить мониторинг"""
        await self.monitoring_service.start()
    
    async def stop_monitoring(self):
        """Остановить мониторинг"""
        await self.monitoring_service.stop()
    
    def get_system_health(self) -> Dict[str, Any]:
        """Получить здоровье системы"""
        return {
            "healthy": self.monitoring_service.is_healthy(),
            "metrics": self.monitoring_service.get_metrics_summary(),
            "timestamp": self.monitoring_service.get_metrics_summary().get("timestamp")
        }
    
    def is_system_healthy(self) -> bool:
        """Проверить здоровье системы"""
        return self.monitoring_service.is_healthy()

class AlertAdapter:
    """Адаптер для алертов"""
    
    def __init__(self, alert_service: IAlertService):
        self.alert_service = alert_service
    
    def add_alert_rule(self, rule) -> None:
        """Добавить правило алерта"""
        self.alert_service.add_alert_rule(rule)
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Получить активные алерты"""
        return self.alert_service.get_active_alerts()
    
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Получить историю алертов"""
        return self.alert_service.get_alert_history(limit)
    
    def has_critical_alerts(self) -> bool:
        """Проверить наличие критических алертов"""
        alerts = self.get_active_alerts()
        return any(alert.get("severity") == "critical" for alert in alerts)

class TracingAdapter:
    """Адаптер для трейсинга"""
    
    def __init__(self, tracing_service: ITracingService):
        self.tracing_service = tracing_service
    
    def start_trace(self, operation_name: str, service_name: str = "samokoder") -> str:
        """Начать новый трейс"""
        return self.tracing_service.start_trace(operation_name, service_name)
    
    def start_span(self, trace_id: str, operation_name: str, 
                   parent_span_id: Optional[str] = None) -> str:
        """Начать новый спан"""
        return self.tracing_service.start_span(trace_id, operation_name, parent_span_id)
    
    def finish_span(self, span_id: str, status: str = "completed", 
                   error: Optional[Exception] = None):
        """Завершить спан"""
        self.tracing_service.finish_span(span_id, status, error)
    
    def finish_trace(self, trace_id: str):
        """Завершить трейс"""
        self.tracing_service.finish_trace(trace_id)
    
    def get_trace_statistics(self) -> Dict[str, Any]:
        """Получить статистику трейсов"""
        return self.tracing_service.get_trace_statistics()