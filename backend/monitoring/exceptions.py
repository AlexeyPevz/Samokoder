"""
Специфичные исключения для мониторинга
"""

class MonitoringError(Exception):
    """Базовое исключение для мониторинга"""
    pass

class MetricsCollectionError(MonitoringError):
    """Ошибка сбора метрик"""
    pass

class AlertProcessingError(MonitoringError):
    """Ошибка обработки алертов"""
    pass

class TracingError(MonitoringError):
    """Ошибка трейсинга"""
    pass

class DashboardError(MonitoringError):
    """Ошибка дашборда"""
    pass

class SystemMetricsError(MetricsCollectionError):
    """Ошибка сбора системных метрик"""
    pass

class ApplicationMetricsError(MetricsCollectionError):
    """Ошибка сбора метрик приложения"""
    pass

class PrometheusError(MetricsCollectionError):
    """Ошибка работы с Prometheus"""
    pass