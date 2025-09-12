"""
Фабрика адаптеров
Создает адаптеры для уменьшения связности
"""

import logging
from typing import Dict, Any, Optional
from backend.core.dependency_injection import get_container

logger = logging.getLogger(__name__)

class AdapterFactory:
    """Фабрика адаптеров"""
    
    def __init__(self):
        self.container = get_container()
        self._adapters: Dict[str, Any] = {}
    
    def get_monitoring_adapter(self):
        """Получить адаптер мониторинга"""
        if "monitoring_adapter" not in self._adapters:
            from backend.adapters.monitoring_adapter import MonitoringAdapter
            from backend.monitoring.advanced_monitoring import AdvancedMonitoring
            
            monitoring_service = self.container.get(AdvancedMonitoring)
            self._adapters["monitoring_adapter"] = MonitoringAdapter(monitoring_service)
        
        return self._adapters["monitoring_adapter"]
    
    def get_alert_adapter(self):
        """Получить адаптер алертов"""
        if "alert_adapter" not in self._adapters:
            from backend.adapters.monitoring_adapter import AlertAdapter
            from backend.monitoring.advanced_monitoring import AdvancedMonitoring
            
            monitoring_service = self.container.get(AdvancedMonitoring)
            self._adapters["alert_adapter"] = AlertAdapter(monitoring_service)
        
        return self._adapters["alert_adapter"]
    
    def get_tracing_adapter(self):
        """Получить адаптер трейсинга"""
        if "tracing_adapter" not in self._adapters:
            from backend.adapters.monitoring_adapter import TracingAdapter
            from backend.monitoring.advanced_monitoring import AdvancedMonitoring
            
            monitoring_service = self.container.get(AdvancedMonitoring)
            self._adapters["tracing_adapter"] = TracingAdapter(monitoring_service)
        
        return self._adapters["tracing_adapter"]
    
    def get_ai_adapter(self):
        """Получить адаптер AI"""
        if "ai_adapter" not in self._adapters:
            from backend.adapters.ai_adapter import AIAdapter
            from backend.services.ai.ai_service import AIService
            
            ai_service = self.container.get(AIService)
            self._adapters["ai_adapter"] = AIAdapter(ai_service)
        
        return self._adapters["ai_adapter"]
    
    def get_security_adapter(self):
        """Получить адаптер безопасности"""
        if "security_adapter" not in self._adapters:
            from backend.adapters.security_adapter import SecurityAdapter
            from backend.services.rbac_service import RBACService
            from backend.services.mfa_service import MFAService
            
            rbac_service = self.container.get(RBACService)
            mfa_service = self.container.get(MFAService)
            self._adapters["security_adapter"] = SecurityAdapter(rbac_service, mfa_service)
        
        return self._adapters["security_adapter"]
    
    def clear_adapters(self):
        """Очистить все адаптеры"""
        self._adapters.clear()
        logger.info("All adapters cleared")
    
    def get_available_adapters(self) -> list:
        """Получить список доступных адаптеров"""
        return list(self._adapters.keys())

# Глобальная фабрика адаптеров
_adapter_factory: Optional[AdapterFactory] = None

def get_adapter_factory() -> AdapterFactory:
    """Получить фабрику адаптеров"""
    global _adapter_factory
    if _adapter_factory is None:
        _adapter_factory = AdapterFactory()
    return _adapter_factory