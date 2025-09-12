"""
Метрики и сбор данных
"""

import asyncio
import logging
import time
import psutil
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict, deque

from .exceptions import MetricsCollectionError, SystemMetricsError

try:
    from prometheus_client import Counter, Histogram, Gauge, Summary
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class MetricData:
    """Структура для метрики"""
    name: str
    value: float
    labels: Dict[str, str]
    timestamp: datetime
    metric_type: str  # counter, gauge, histogram, summary

class MetricsCollector:
    """
    Сборщик метрик для системы мониторинга
    
    Обеспечивает сбор и управление метриками приложения, включая:
    - Prometheus метрики (счетчики, gauges, гистограммы)
    - Системные метрики (CPU, память, диск, сеть)
    - Кастомные метрики приложения
    
    Attributes:
        metrics: Словарь с Prometheus метриками
        custom_metrics: Словарь с кастомными метриками
        _last_collection: Время последнего сбора метрик
    
    Example:
        >>> collector = MetricsCollector()
        >>> collector.increment_counter('requests_total', {'method': 'GET'})
        >>> collector.set_gauge('memory_usage', 85.5)
        >>> await collector.collect_system_metrics()
    """
    
    def __init__(self):
        self.metrics: Dict[str, Any] = {}
        self.custom_metrics: Dict[str, MetricData] = {}
        self._setup_prometheus_metrics()
    
    def _setup_prometheus_metrics(self):
        """Настройка Prometheus метрик"""
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus not available, using fallback metrics")
            return
            
        self.metrics = {
            'http_requests_total': Counter(
                'http_requests_total', 
                'Total HTTP requests',
                ['method', 'endpoint', 'status']
            ),
            'http_request_duration_seconds': Histogram(
                'http_request_duration_seconds',
                'HTTP request duration',
                ['method', 'endpoint']
            ),
            'active_connections': Gauge(
                'active_connections',
                'Number of active connections'
            ),
            'memory_usage_bytes': Gauge(
                'memory_usage_bytes',
                'Memory usage in bytes'
            ),
            'cpu_usage_percent': Gauge(
                'cpu_usage_percent',
                'CPU usage percentage'
            ),
            'database_connections': Gauge(
                'database_connections',
                'Number of database connections'
            ),
            'queue_size': Gauge(
                'queue_size',
                'Queue size'
            ),
            'error_rate': Gauge(
                'error_rate',
                'Error rate percentage'
            )
        }
    
    def increment_counter(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Увеличить счетчик метрики на 1
        
        Args:
            name: Название метрики
            labels: Метки для метрики (опционально)
            
        Example:
            >>> collector.increment_counter('http_requests_total', {'method': 'GET', 'status': '200'})
        """
        if name in self.metrics and PROMETHEUS_AVAILABLE:
            self.metrics[name].labels(**(labels or {})).inc()
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Установить значение gauge метрики
        
        Args:
            name: Название метрики
            value: Значение для установки
            labels: Метки для метрики (опционально)
            
        Example:
            >>> collector.set_gauge('memory_usage_percent', 85.5, {'host': 'server1'})
        """
        if name in self.metrics and PROMETHEUS_AVAILABLE:
            self.metrics[name].labels(**(labels or {})).set(value)
    
    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Наблюдать значение в гистограмме
        
        Args:
            name: Название метрики
            value: Значение для наблюдения
            labels: Метки для метрики (опционально)
            
        Example:
            >>> collector.observe_histogram('request_duration_seconds', 0.5, {'endpoint': '/api/users'})
        """
        if name in self.metrics and PROMETHEUS_AVAILABLE:
            self.metrics[name].labels(**(labels or {})).observe(value)
    
    def add_custom_metric(self, name: str, value: float, metric_type: str, 
                         labels: Optional[Dict[str, str]] = None) -> None:
        """
        Добавить кастомную метрику
        
        Args:
            name: Название метрики
            value: Значение метрики
            metric_type: Тип метрики (counter, gauge, histogram, summary)
            labels: Метки для метрики (опционально)
            
        Example:
            >>> collector.add_custom_metric('custom_events', 42, 'counter', {'type': 'user_action'})
        """
        self.custom_metrics[name] = MetricData(
            name=name,
            value=value,
            labels=labels or {},
            timestamp=datetime.now(),
            metric_type=metric_type
        )
    
    async def collect_system_metrics(self) -> None:
        """
        Сбор системных метрик
        
        Собирает метрики системы:
        - CPU usage (процент использования)
        - Memory usage (использование памяти в байтах)
        - Disk usage (использование диска в байтах)
        - Network I/O (отправленные/полученные байты)
        
        Raises:
            SystemMetricsError: При ошибках доступа к процессам
            MetricsCollectionError: При других ошибках сбора метрик
            
        Example:
            >>> await collector.collect_system_metrics()
        """
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.set_gauge('cpu_usage_percent', cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.set_gauge('memory_usage_bytes', memory.used)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.set_gauge('disk_usage_bytes', disk.used)
            
            # Network stats
            net_io = psutil.net_io_counters()
            self.set_gauge('network_bytes_sent', net_io.bytes_sent)
            self.set_gauge('network_bytes_recv', net_io.bytes_recv)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.warning(f"Process access error during metrics collection: {e}")
            raise SystemMetricsError(f"Process access error: {e}") from e
        except OSError as e:
            logger.error(f"OS error during metrics collection: {e}")
            raise SystemMetricsError(f"OS error: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error collecting system metrics: {e}")
            raise MetricsCollectionError(f"Unexpected error: {e}") from e
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Получить сводку метрик"""
        summary = {}
        
        if PROMETHEUS_AVAILABLE:
            for name, metric in self.metrics.items():
                try:
                    if hasattr(metric, '_value'):
                        summary[name] = metric._value.get()
                    elif hasattr(metric, '_sum'):
                        summary[name] = {
                            'sum': metric._sum.get(),
                            'count': metric._count.get()
                        }
                except Exception as e:
                    logger.debug(f"Error getting metric {name}: {e}")
        
        # Добавляем кастомные метрики
        for name, metric in self.custom_metrics.items():
            summary[f"custom_{name}"] = {
                'value': metric.value,
                'labels': metric.labels,
                'timestamp': metric.timestamp.isoformat(),
                'type': metric.metric_type
            }
        
        return summary