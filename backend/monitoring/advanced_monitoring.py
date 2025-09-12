"""
Продвинутая система мониторинга и логирования
Включает метрики, трейсинг, алерты и дашборды
"""

import asyncio
import logging
import time
import psutil
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import threading
from contextlib import asynccontextmanager

try:
    from prometheus_client import Counter, Histogram, Gauge, Summary, start_http_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

from config.settings import settings

logger = logging.getLogger(__name__)

@dataclass
class MetricData:
    """Структура для метрики"""
    name: str
    value: float
    labels: Dict[str, str]
    timestamp: datetime
    metric_type: str  # counter, gauge, histogram, summary

@dataclass
class AlertRule:
    """Правило для алертов"""
    name: str
    condition: Callable[[Dict[str, Any]], bool]
    severity: str  # critical, warning, info
    message: str
    cooldown: int = 300  # секунды

@dataclass
class Alert:
    """Алерт"""
    rule_name: str
    severity: str
    message: str
    timestamp: datetime
    resolved: bool = False

class PrometheusMetrics:
    """Prometheus метрики"""
    
    def __init__(self):
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus client not available")
            return
        
        # HTTP метрики
        self.http_requests_total = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status_code']
        )
        
        self.http_request_duration = Histogram(
            'http_request_duration_seconds',
            'HTTP request duration',
            ['method', 'endpoint']
        )
        
        # AI метрики
        self.ai_requests_total = Counter(
            'ai_requests_total',
            'Total AI requests',
            ['provider', 'model', 'status']
        )
        
        self.ai_request_duration = Histogram(
            'ai_request_duration_seconds',
            'AI request duration',
            ['provider', 'model']
        )
        
        self.ai_tokens_used = Counter(
            'ai_tokens_used_total',
            'Total AI tokens used',
            ['provider', 'model']
        )
        
        self.ai_cost_usd = Counter(
            'ai_cost_usd_total',
            'Total AI cost in USD',
            ['provider', 'model']
        )
        
        # Системные метрики
        self.active_connections = Gauge(
            'active_connections',
            'Active database connections'
        )
        
        self.active_projects = Gauge(
            'active_projects',
            'Active projects count'
        )
        
        self.memory_usage = Gauge(
            'memory_usage_bytes',
            'Memory usage in bytes'
        )
        
        self.cpu_usage = Gauge(
            'cpu_usage_percent',
            'CPU usage percentage'
        )
        
        self.disk_usage = Gauge(
            'disk_usage_bytes',
            'Disk usage in bytes'
        )
        
        # Бизнес метрики
        self.users_total = Gauge(
            'users_total',
            'Total number of users'
        )
        
        self.projects_total = Gauge(
            'projects_total',
            'Total number of projects'
        )
        
        self.api_keys_total = Gauge(
            'api_keys_total',
            'Total number of API keys'
        )
        
        # Ошибки
        self.errors_total = Counter(
            'errors_total',
            'Total errors',
            ['error_type', 'component']
        )
        
        # Rate limiting
        self.rate_limit_hits = Counter(
            'rate_limit_hits_total',
            'Rate limit hits',
            ['endpoint', 'user_id']
        )
    
    def record_http_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Записывает HTTP запрос"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        self.http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code)
        ).inc()
        
        self.http_request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def record_ai_request(self, provider: str, model: str, duration: float, tokens: int, cost: float, success: bool):
        """Записывает AI запрос"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        status = "success" if success else "error"
        
        self.ai_requests_total.labels(
            provider=provider,
            model=model,
            status=status
        ).inc()
        
        if success:
            self.ai_request_duration.labels(
                provider=provider,
                model=model
            ).observe(duration)
            
            self.ai_tokens_used.labels(
                provider=provider,
                model=model
            ).inc(tokens)
            
            self.ai_cost_usd.labels(
                provider=provider,
                model=model
            ).inc(cost)
    
    def record_error(self, error_type: str, component: str):
        """Записывает ошибку"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        self.errors_total.labels(
            error_type=error_type,
            component=component
        ).inc()
    
    def record_rate_limit_hit(self, endpoint: str, user_id: str):
        """Записывает срабатывание rate limit"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        self.rate_limit_hits.labels(
            endpoint=endpoint,
            user_id=user_id
        ).inc()
    
    def update_system_metrics(self):
        """Обновляет системные метрики"""
        if not PROMETHEUS_AVAILABLE:
            return
        
        # Память
        memory = psutil.virtual_memory()
        self.memory_usage.set(memory.used)
        
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        self.cpu_usage.set(cpu_percent)
        
        # Диск
        disk = psutil.disk_usage('/')
        self.disk_usage.set(disk.used)

class StructuredLogger:
    """Структурированное логирование"""
    
    def __init__(self):
        if STRUCTLOG_AVAILABLE:
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.UnicodeDecoder(),
                    structlog.processors.JSONRenderer()
                ],
                context_class=dict,
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
            self.logger = structlog.get_logger()
        else:
            self.logger = logging.getLogger(__name__)
    
    def log_request(self, method: str, endpoint: str, status_code: int, duration: float, user_id: str = None):
        """Логирует HTTP запрос"""
        log_data = {
            "event": "http_request",
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "duration": duration,
            "user_id": user_id
        }
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info("HTTP request", **log_data)
        else:
            safe_method = log_sanitizer.sanitize_string(method)
            safe_endpoint = log_sanitizer.sanitize_string(endpoint)
            self.logger.info(f"HTTP {safe_method} {safe_endpoint} {status_code} {duration:.3f}s")
    
    def log_ai_request(self, provider: str, model: str, tokens: int, cost: float, duration: float, success: bool):
        """Логирует AI запрос"""
        log_data = {
            "event": "ai_request",
            "provider": provider,
            "model": model,
            "tokens": tokens,
            "cost": cost,
            "duration": duration,
            "success": success
        }
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info("AI request", **log_data)
        else:
            safe_provider = log_sanitizer.sanitize_string(provider)
            safe_model = log_sanitizer.sanitize_string(model)
            self.logger.info(f"AI {safe_provider}/{safe_model} {tokens} tokens ${cost:.4f} {duration:.3f}s")
    
    def log_error(self, error: Exception, context: Dict[str, Any] = None):
        """Логирует ошибку"""
        log_data = {
            "event": "error",
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context or {}
        }
        
        if STRUCTLOG_AVAILABLE:
            self.logger.error("Application error", **log_data)
        else:
            safe_error_type = log_sanitizer.sanitize_string(type(error).__name__)
            safe_error_msg = log_sanitizer.sanitize_string(str(error))
            self.logger.error(f"Error: {safe_error_type}: {safe_error_msg}")
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Логирует событие безопасности"""
        log_data = {
            "event": "security",
            "security_event": event_type,
            "details": details
        }
        
        if STRUCTLOG_AVAILABLE:
            self.logger.warning("Security event", **log_data)
        else:
            safe_event_type = log_sanitizer.sanitize_string(event_type)
            safe_details = log_sanitizer.sanitize_string(str(details))
            self.logger.warning(f"Security: {safe_event_type} - {safe_details}")

class AlertManager:
    """Менеджер алертов"""
    
    def __init__(self):
        self.alerts: List[Alert] = []
        self.rules: List[AlertRule] = []
        self.alert_history: deque = deque(maxlen=1000)
        self.last_alert_times: Dict[str, datetime] = {}
        
        # Настраиваем правила алертов
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Настраивает правила алертов по умолчанию"""
        
        # Высокое использование CPU
        self.add_rule(AlertRule(
            name="high_cpu_usage",
            condition=lambda metrics: metrics.get("cpu_usage", 0) > 80,
            severity="warning",
            message="High CPU usage detected",
            cooldown=300
        ))
        
        # Высокое использование памяти
        self.add_rule(AlertRule(
            name="high_memory_usage",
            condition=lambda metrics: metrics.get("memory_usage_percent", 0) > 85,
            severity="warning",
            message="High memory usage detected",
            cooldown=300
        ))
        
        # Высокий процент ошибок
        self.add_rule(AlertRule(
            name="high_error_rate",
            condition=lambda metrics: metrics.get("error_rate", 0) > 5,
            severity="critical",
            message="High error rate detected",
            cooldown=60
        ))
        
        # Много активных соединений
        self.add_rule(AlertRule(
            name="high_connection_count",
            condition=lambda metrics: metrics.get("active_connections", 0) > 50,
            severity="warning",
            message="High number of active connections",
            cooldown=300
        ))
        
        # Медленные запросы
        self.add_rule(AlertRule(
            name="slow_requests",
            condition=lambda metrics: metrics.get("avg_response_time", 0) > 5,
            severity="warning",
            message="Slow requests detected",
            cooldown=300
        ))
    
    def add_rule(self, rule: AlertRule):
        """Добавляет правило алерта"""
        self.rules.append(rule)
    
    def check_alerts(self, metrics: Dict[str, Any]):
        """Проверяет правила алертов"""
        current_time = datetime.now()
        
        for rule in self.rules:
            try:
                if rule.condition(metrics):
                    # Проверяем cooldown
                    last_alert = self.last_alert_times.get(rule.name)
                    if last_alert and (current_time - last_alert).seconds < rule.cooldown:
                        continue
                    
                    # Создаем алерт
                    alert = Alert(
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=rule.message,
                        timestamp=current_time
                    )
                    
                    self.alerts.append(alert)
                    self.alert_history.append(alert)
                    self.last_alert_times[rule.name] = current_time
                    
                    # Логируем алерт
                    safe_severity = log_sanitizer.sanitize_string(rule.severity.upper())
                    safe_message = log_sanitizer.sanitize_string(rule.message)
                    logger.warning(f"ALERT: {safe_severity} - {safe_message}")
                    
            except Exception as e:
                safe_rule_name = log_sanitizer.sanitize_string(rule.name)
                safe_error = log_sanitizer.sanitize_string(str(e))
                logger.error(f"Error checking alert rule {safe_rule_name}: {safe_error}")
    
    def get_active_alerts(self) -> List[Alert]:
        """Возвращает активные алерты"""
        return [alert for alert in self.alerts if not alert.resolved]
    
    def resolve_alert(self, rule_name: str):
        """Разрешает алерт"""
        for alert in self.alerts:
            if alert.rule_name == rule_name and not alert.resolved:
                alert.resolved = True
                safe_rule_name = log_sanitizer.sanitize_string(rule_name)
                logger.info(f"Alert resolved: {safe_rule_name}")

class PerformanceProfiler:
    """Профилировщик производительности"""
    
    def __init__(self):
        self.request_times: deque = deque(maxlen=1000)
        self.ai_request_times: deque = deque(maxlen=1000)
        self.database_query_times: deque = deque(maxlen=1000)
        self.error_counts: Dict[str, int] = defaultdict(int)
    
    def record_request_time(self, duration: float):
        """Записывает время запроса"""
        self.request_times.append(duration)
    
    def record_ai_request_time(self, duration: float):
        """Записывает время AI запроса"""
        self.ai_request_times.append(duration)
    
    def record_database_query_time(self, duration: float):
        """Записывает время запроса к БД"""
        self.database_query_times.append(duration)
    
    def record_error(self, error_type: str):
        """Записывает ошибку"""
        self.error_counts[error_type] += 1
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Возвращает статистику производительности"""
        stats = {}
        
        if self.request_times:
            stats["avg_response_time"] = sum(self.request_times) / len(self.request_times)
            stats["max_response_time"] = max(self.request_times)
            stats["min_response_time"] = min(self.request_times)
            stats["p95_response_time"] = sorted(self.request_times)[int(len(self.request_times) * 0.95)]
        
        if self.ai_request_times:
            stats["avg_ai_response_time"] = sum(self.ai_request_times) / len(self.ai_request_times)
            stats["max_ai_response_time"] = max(self.ai_request_times)
        
        if self.database_query_times:
            stats["avg_db_query_time"] = sum(self.database_query_times) / len(self.database_query_times)
            stats["max_db_query_time"] = max(self.database_query_times)
        
        stats["error_counts"] = dict(self.error_counts)
        
        return stats

class AdvancedMonitoring:
    """Продвинутая система мониторинга"""
    
    def __init__(self):
        self.metrics = PrometheusMetrics()
        self.logger = StructuredLogger()
        self.alert_manager = AlertManager()
        self.profiler = PerformanceProfiler()
        
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        
        # Запускаем фоновые задачи
        self._start_background_tasks()
    
    def _start_background_tasks(self):
        """Запускает фоновые задачи мониторинга"""
        async def update_metrics():
            while True:
                try:
                    self._update_system_metrics()
                    self._check_alerts()
                    await asyncio.sleep(30)  # Обновляем каждые 30 секунд
                except Exception as e:
                    safe_error = log_sanitizer.sanitize_string(str(e))
                    logger.error(f"Error in background monitoring: {safe_error}")
                    await asyncio.sleep(60)
        
        # Запускаем асинхронную задачу
        asyncio.create_task(update_metrics())
    
    def _update_system_metrics(self):
        """Обновляет системные метрики"""
        try:
            # Обновляем Prometheus метрики
            self.metrics.update_system_metrics()
            
            # Обновляем бизнес метрики
            # Здесь можно добавить запросы к БД для получения актуальных данных
            
        except Exception as e:
            safe_error = log_sanitizer.sanitize_string(str(e))
            logger.error(f"Error updating system metrics: {safe_error}")
    
    def _check_alerts(self):
        """Проверяет алерты"""
        try:
            metrics = self.get_current_metrics()
            self.alert_manager.check_alerts(metrics)
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")
    
    def record_http_request(self, method: str, endpoint: str, status_code: int, duration: float, user_id: str = None):
        """Записывает HTTP запрос"""
        self.request_count += 1
        if status_code >= 400:
            self.error_count += 1
        
        # Prometheus метрики
        self.metrics.record_http_request(method, endpoint, status_code, duration)
        
        # Структурированное логирование
        self.logger.log_request(method, endpoint, status_code, duration, user_id)
        
        # Профилирование
        self.profiler.record_request_time(duration)
    
    def record_ai_request(self, provider: str, model: str, tokens: int, cost: float, duration: float, success: bool):
        """Записывает AI запрос"""
        # Prometheus метрики
        self.metrics.record_ai_request(provider, model, duration, tokens, cost, success)
        
        # Структурированное логирование
        self.logger.log_ai_request(provider, model, tokens, cost, duration, success)
        
        # Профилирование
        self.profiler.record_ai_request_time(duration)
    
    def record_error(self, error: Exception, component: str = "unknown"):
        """Записывает ошибку"""
        self.error_count += 1
        
        # Prometheus метрики
        self.metrics.record_error(type(error).__name__, component)
        
        # Структурированное логирование
        self.logger.log_error(error, {"component": component})
        
        # Профилирование
        self.profiler.record_error(type(error).__name__)
    
    def record_security_event(self, event_type: str, details: Dict[str, Any]):
        """Записывает событие безопасности"""
        self.logger.log_security_event(event_type, details)
    
    def record_rate_limit_hit(self, endpoint: str, user_id: str):
        """Записывает срабатывание rate limit"""
        self.metrics.record_rate_limit_hit(endpoint, user_id)
        self.record_security_event("rate_limit_hit", {
            "endpoint": endpoint,
            "user_id": user_id
        })
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Возвращает текущие метрики"""
        uptime = time.time() - self.start_time
        
        # Системные метрики
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent()
        disk = psutil.disk_usage('/')
        
        # Производительность
        perf_stats = self.profiler.get_performance_stats()
        
        # Алерты
        active_alerts = self.alert_manager.get_active_alerts()
        
        return {
            "uptime": uptime,
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": (self.error_count / self.request_count * 100) if self.request_count > 0 else 0,
            "memory_usage": memory.used,
            "memory_usage_percent": memory.percent,
            "cpu_usage": cpu_percent,
            "disk_usage": disk.used,
            "disk_usage_percent": (disk.used / disk.total * 100),
            "active_alerts_count": len(active_alerts),
            "active_alerts": [asdict(alert) for alert in active_alerts],
            **perf_stats
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Возвращает статус здоровья системы"""
        metrics = self.get_current_metrics()
        active_alerts = self.alert_manager.get_active_alerts()
        
        # Определяем общий статус
        critical_alerts = [alert for alert in active_alerts if alert.severity == "critical"]
        warning_alerts = [alert for alert in active_alerts if alert.severity == "warning"]
        
        if critical_alerts:
            status = "critical"
        elif warning_alerts:
            status = "warning"
        elif metrics["error_rate"] > 1:
            status = "degraded"
        else:
            status = "healthy"
        
        return {
            "status": status,
            "uptime": metrics["uptime"],
            "services": {
                "database": "healthy",  # Здесь должна быть проверка БД
                "redis": "healthy",     # Здесь должна быть проверка Redis
                "ai_services": "healthy"  # Здесь должна быть проверка AI сервисов
            },
            "metrics": metrics,
            "alerts": {
                "active": len(active_alerts),
                "critical": len(critical_alerts),
                "warning": len(warning_alerts)
            }
        }
    
    @asynccontextmanager
    async def monitor_request(self, method: str, endpoint: str, user_id: str = None):
        """Контекстный менеджер для мониторинга запроса"""
        start_time = time.time()
        status_code = 200
        
        try:
            yield
        except Exception as e:
            status_code = 500
            self.record_error(e, "http_request")
            raise
        finally:
            duration = time.time() - start_time
            self.record_http_request(method, endpoint, status_code, duration, user_id)

# Глобальный экземпляр мониторинга
advanced_monitoring = AdvancedMonitoring()

# Функции для удобного доступа
def record_http_request(method: str, endpoint: str, status_code: int, duration: float, user_id: str = None):
    """Записывает HTTP запрос"""
    advanced_monitoring.record_http_request(method, endpoint, status_code, duration, user_id)

def record_ai_request(provider: str, model: str, tokens: int, cost: float, duration: float, success: bool):
    """Записывает AI запрос"""
    advanced_monitoring.record_ai_request(provider, model, tokens, cost, duration, success)

def record_error(error: Exception, component: str = "unknown"):
    """Записывает ошибку"""
    advanced_monitoring.record_error(error, component)

def record_security_event(event_type: str, details: Dict[str, Any]):
    """Записывает событие безопасности"""
    advanced_monitoring.record_security_event(event_type, details)

def get_health_status() -> Dict[str, Any]:
    """Возвращает статус здоровья"""
    return advanced_monitoring.get_health_status()

def get_current_metrics() -> Dict[str, Any]:
    """Возвращает текущие метрики"""
    return advanced_monitoring.get_current_metrics()

# Запуск Prometheus сервера
if PROMETHEUS_AVAILABLE and settings.enable_metrics:
    try:
        start_http_server(settings.metrics_port)
        logger.info(f"Prometheus metrics server started on port {settings.metrics_port}")
    except Exception as e:
        logger.error(f"Failed to start Prometheus metrics server: {e}")