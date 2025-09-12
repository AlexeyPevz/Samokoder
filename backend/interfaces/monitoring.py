"""
Интерфейсы для мониторинга
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime

class IMonitoringService(ABC):
    """Интерфейс сервиса мониторинга"""
    
    @abstractmethod
    async def start(self):
        """Запустить мониторинг"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Остановить мониторинг"""
        pass
    
    @abstractmethod
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Получить сводку метрик"""
        pass
    
    @abstractmethod
    def is_healthy(self) -> bool:
        """Проверить здоровье системы"""
        pass

class IAlertService(ABC):
    """Интерфейс сервиса алертов"""
    
    @abstractmethod
    def add_alert_rule(self, rule) -> None:
        """Добавить правило алерта"""
        pass
    
    @abstractmethod
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Получить активные алерты"""
        pass
    
    @abstractmethod
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Получить историю алертов"""
        pass

class ITracingService(ABC):
    """Интерфейс сервиса трейсинга"""
    
    @abstractmethod
    def start_trace(self, operation_name: str, service_name: str = "samokoder") -> str:
        """Начать новый трейс"""
        pass
    
    @abstractmethod
    def start_span(self, trace_id: str, operation_name: str, 
                   parent_span_id: Optional[str] = None) -> str:
        """Начать новый спан"""
        pass
    
    @abstractmethod
    def finish_span(self, span_id: str, status: str = "completed", 
                   error: Optional[Exception] = None):
        """Завершить спан"""
        pass
    
    @abstractmethod
    def finish_trace(self, trace_id: str):
        """Завершить трейс"""
        pass
    
    @abstractmethod
    def get_trace_statistics(self) -> Dict[str, Any]:
        """Получить статистику трейсов"""
        pass