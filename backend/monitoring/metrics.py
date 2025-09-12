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
    """Сборщик метрик"""
    
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
    
    def increment_counter(self, name: str, labels: Dict[str, str] = None):
        """Увеличить счетчик"""
        if name in self.metrics and PROMETHEUS_AVAILABLE:
            self.metrics[name].labels(**(labels or {})).inc()
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Установить значение gauge"""
        if name in self.metrics and PROMETHEUS_AVAILABLE:
            self.metrics[name].labels(**(labels or {})).set(value)
    
    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Наблюдать гистограмму"""
        if name in self.metrics and PROMETHEUS_AVAILABLE:
            self.metrics[name].labels(**(labels or {})).observe(value)
    
    def add_custom_metric(self, name: str, value: float, metric_type: str, 
                         labels: Dict[str, str] = None):
        """Добавить кастомную метрику"""
        self.custom_metrics[name] = MetricData(
            name=name,
            value=value,
            labels=labels or {},
            timestamp=datetime.now(),
            metric_type=metric_type
        )
    
    async def collect_system_metrics(self):
        """Сбор системных метрик"""
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
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
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