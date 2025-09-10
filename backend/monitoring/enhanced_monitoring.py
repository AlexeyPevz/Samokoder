"""
Улучшенная система мониторинга с детальными метриками
"""

import time
import structlog
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque
import asyncio
import psutil
import os

from prometheus_client import Counter, Histogram, Gauge, Summary, Info
from fastapi import Request, Response

logger = structlog.get_logger(__name__)

@dataclass
class SystemMetrics:
    """Метрики системы"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    memory_available_mb: float = 0.0
    disk_usage_percent: float = 0.0
    disk_free_gb: float = 0.0
    load_average: List[float] = field(default_factory=list)
    uptime_seconds: float = 0.0
    process_count: int = 0
    network_connections: int = 0

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

class EnhancedMonitoring:
    """Улучшенная система мониторинга"""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_times = deque(maxlen=1000)
        self.error_counts = defaultdict(int)
        self.endpoint_metrics = defaultdict(lambda: {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'response_times': deque(maxlen=100),
            'last_request': None
        })
        
        # Prometheus метрики
        self._setup_prometheus_metrics()
        
        # Запускаем задачу сбора метрик
        asyncio.create_task(self._collect_metrics_loop())
    
    def _setup_prometheus_metrics(self):
        """Настройка Prometheus метрик"""
        # HTTP метрики
        self.http_requests_total = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status_code']
        )
        
        self.http_request_duration = Histogram(
            'http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )
        
        self.http_request_size = Histogram(
            'http_request_size_bytes',
            'HTTP request size in bytes',
            ['method', 'endpoint'],
            buckets=(100, 1000, 10000, 100000, 1000000, 10000000)
        )
        
        self.http_response_size = Histogram(
            'http_response_size_bytes',
            'HTTP response size in bytes',
            ['method', 'endpoint'],
            buckets=(100, 1000, 10000, 100000, 1000000, 10000000)
        )
        
        # Системные метрики
        self.system_cpu_percent = Gauge(
            'system_cpu_percent',
            'CPU usage percentage'
        )
        
        self.system_memory_percent = Gauge(
            'system_memory_percent',
            'Memory usage percentage'
        )
        
        self.system_memory_used_bytes = Gauge(
            'system_memory_used_bytes',
            'Memory used in bytes'
        )
        
        self.system_disk_usage_percent = Gauge(
            'system_disk_usage_percent',
            'Disk usage percentage'
        )
        
        self.system_load_average = Gauge(
            'system_load_average',
            'System load average',
            ['period']
        )
        
        self.system_uptime_seconds = Gauge(
            'system_uptime_seconds',
            'System uptime in seconds'
        )
        
        # Метрики приложения
        self.app_active_connections = Gauge(
            'app_active_connections',
            'Active connections'
        )
        
        self.app_error_rate = Gauge(
            'app_error_rate',
            'Error rate percentage'
        )
        
        self.app_requests_per_second = Gauge(
            'app_requests_per_second',
            'Requests per second'
        )
        
        # AI метрики
        self.ai_requests_total = Counter(
            'ai_requests_total',
            'Total AI requests',
            ['provider', 'model', 'status']
        )
        
        self.ai_request_duration = Histogram(
            'ai_request_duration_seconds',
            'AI request duration in seconds',
            ['provider', 'model'],
            buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
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
        
        # Информационные метрики
        self.app_info = Info(
            'app_info',
            'Application information'
        )
        self.app_info.info({
            'version': '1.0.0',
            'name': 'samokoder-backend',
            'environment': os.getenv('ENVIRONMENT', 'development')
        })
    
    async def _collect_metrics_loop(self):
        """Цикл сбора метрик"""
        while True:
            try:
                await asyncio.sleep(30)  # Собираем метрики каждые 30 секунд
                await self._update_system_metrics()
                await self._update_application_metrics()
            except Exception as e:
                logger.error(
                    "metrics_collection_error",
                    error=str(e),
                    error_type=type(e).__name__
                )
    
    async def _update_system_metrics(self):
        """Обновление системных метрик"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            self.system_cpu_percent.set(cpu_percent)
            
            # Память
            memory = psutil.virtual_memory()
            self.system_memory_percent.set(memory.percent)
            self.system_memory_used_bytes.set(memory.used)
            
            # Диск
            disk = psutil.disk_usage('/')
            self.system_disk_usage_percent.set(disk.percent)
            
            # Load average
            load_avg = psutil.getloadavg()
            for i, load in enumerate(load_avg):
                self.system_load_average.labels(period=f'{i+1}m').set(load)
            
            # Uptime
            uptime = time.time() - self.start_time
            self.system_uptime_seconds.set(uptime)
            
        except Exception as e:
            logger.error(
                "system_metrics_error",
                error=str(e),
                error_type=type(e).__name__
            )
    
    async def _update_application_metrics(self):
        """Обновление метрик приложения"""
        try:
            # Активные соединения (приблизительно)
            active_connections = len(self.request_times)
            self.app_active_connections.set(active_connections)
            
            # Error rate
            total_requests = sum(metrics['total_requests'] for metrics in self.endpoint_metrics.values())
            total_errors = sum(metrics['failed_requests'] for metrics in self.endpoint_metrics.values())
            error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0
            self.app_error_rate.set(error_rate)
            
            # Requests per second (за последние 60 секунд)
            now = time.time()
            recent_requests = sum(1 for t in self.request_times if now - t < 60)
            self.app_requests_per_second.set(recent_requests)
            
        except Exception as e:
            logger.error(
                "application_metrics_error",
                error=str(e),
                error_type=type(e).__name__
            )
    
    def record_request(self, request: Request, response: Response, duration: float):
        """Записать метрику запроса"""
        try:
            method = request.method
            endpoint = request.url.path
            status_code = response.status_code
            
            # Обновляем счетчики
            self.http_requests_total.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code
            ).inc()
            
            # Обновляем гистограмму времени
            self.http_request_duration.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)
            
            # Обновляем размер запроса
            content_length = request.headers.get('content-length', 0)
            if content_length:
                self.http_request_size.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(int(content_length))
            
            # Обновляем размер ответа
            response_size = response.headers.get('content-length', 0)
            if response_size:
                self.http_response_size.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(int(response_size))
            
            # Обновляем внутренние метрики
            self.request_times.append(time.time())
            
            endpoint_metrics = self.endpoint_metrics[endpoint]
            endpoint_metrics['total_requests'] += 1
            endpoint_metrics['last_request'] = time.time()
            endpoint_metrics['response_times'].append(duration)
            
            if 200 <= status_code < 400:
                endpoint_metrics['successful_requests'] += 1
            else:
                endpoint_metrics['failed_requests'] += 1
                self.error_counts[f"{method} {endpoint}"] += 1
            
        except Exception as e:
            logger.error(
                "record_request_error",
                error=str(e),
                error_type=type(e).__name__
            )
    
    def record_ai_request(self, provider: str, model: str, duration: float, 
                         tokens: int = 0, cost: float = 0.0, status: str = "success"):
        """Записать метрику AI запроса"""
        try:
            self.ai_requests_total.labels(
                provider=provider,
                model=model,
                status=status
            ).inc()
            
            self.ai_request_duration.labels(
                provider=provider,
                model=model
            ).observe(duration)
            
            if tokens > 0:
                self.ai_tokens_used.labels(
                    provider=provider,
                    model=model
                ).inc(tokens)
            
            if cost > 0:
                self.ai_cost_usd.labels(
                    provider=provider,
                    model=model
                ).inc(cost)
                
        except Exception as e:
            logger.error(
                "record_ai_request_error",
                error=str(e),
                error_type=type(e).__name__
            )
    
    def get_system_metrics(self) -> SystemMetrics:
        """Получить системные метрики"""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return SystemMetrics(
                cpu_percent=psutil.cpu_percent(),
                memory_percent=memory.percent,
                memory_used_mb=memory.used / (1024 * 1024),
                memory_available_mb=memory.available / (1024 * 1024),
                disk_usage_percent=disk.percent,
                disk_free_gb=disk.free / (1024 * 1024 * 1024),
                load_average=list(psutil.getloadavg()),
                uptime_seconds=time.time() - self.start_time,
                process_count=len(psutil.pids()),
                network_connections=len(psutil.net_connections())
            )
        except Exception as e:
            logger.error(
                "get_system_metrics_error",
                error=str(e),
                error_type=type(e).__name__
            )
            return SystemMetrics()
    
    def get_application_metrics(self) -> ApplicationMetrics:
        """Получить метрики приложения"""
        try:
            total_requests = sum(metrics['total_requests'] for metrics in self.endpoint_metrics.values())
            successful_requests = sum(metrics['successful_requests'] for metrics in self.endpoint_metrics.values())
            failed_requests = sum(metrics['failed_requests'] for metrics in self.endpoint_metrics.values())
            
            # Вычисляем среднее время ответа
            all_response_times = []
            for metrics in self.endpoint_metrics.values():
                all_response_times.extend(metrics['response_times'])
            
            if all_response_times:
                avg_response_time = sum(all_response_times) / len(all_response_times)
                sorted_times = sorted(all_response_times)
                p95_index = int(len(sorted_times) * 0.95)
                p99_index = int(len(sorted_times) * 0.99)
                p95_response_time = sorted_times[p95_index] if p95_index < len(sorted_times) else sorted_times[-1]
                p99_response_time = sorted_times[p99_index] if p99_index < len(sorted_times) else sorted_times[-1]
            else:
                avg_response_time = 0.0
                p95_response_time = 0.0
                p99_response_time = 0.0
            
            error_rate = (failed_requests / total_requests * 100) if total_requests > 0 else 0.0
            
            # Requests per second за последние 60 секунд
            now = time.time()
            recent_requests = sum(1 for t in self.request_times if now - t < 60)
            requests_per_second = recent_requests / 60.0
            
            return ApplicationMetrics(
                total_requests=total_requests,
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                active_connections=len(self.request_times),
                average_response_time=avg_response_time,
                p95_response_time=p95_response_time,
                p99_response_time=p99_response_time,
                error_rate=error_rate,
                requests_per_second=requests_per_second
            )
        except Exception as e:
            logger.error(
                "get_application_metrics_error",
                error=str(e),
                error_type=type(e).__name__
            )
            return ApplicationMetrics()
    
    def get_health_status(self) -> Dict[str, Any]:
        """Получить статус здоровья системы"""
        try:
            system_metrics = self.get_system_metrics()
            app_metrics = self.get_application_metrics()
            
            # Определяем общий статус
            status = "healthy"
            issues = []
            
            # Проверяем системные метрики
            if system_metrics.cpu_percent > 90:
                status = "degraded"
                issues.append("High CPU usage")
            
            if system_metrics.memory_percent > 90:
                status = "degraded"
                issues.append("High memory usage")
            
            if system_metrics.disk_usage_percent > 90:
                status = "degraded"
                issues.append("High disk usage")
            
            # Проверяем метрики приложения
            if app_metrics.error_rate > 10:
                status = "degraded"
                issues.append("High error rate")
            
            if app_metrics.average_response_time > 5.0:
                status = "degraded"
                issues.append("Slow response times")
            
            return {
                "status": status,
                "timestamp": datetime.utcnow().isoformat(),
                "uptime_seconds": system_metrics.uptime_seconds,
                "issues": issues,
                "system": {
                    "cpu_percent": system_metrics.cpu_percent,
                    "memory_percent": system_metrics.memory_percent,
                    "disk_usage_percent": system_metrics.disk_usage_percent,
                    "load_average": system_metrics.load_average
                },
                "application": {
                    "total_requests": app_metrics.total_requests,
                    "error_rate": app_metrics.error_rate,
                    "average_response_time": app_metrics.average_response_time,
                    "requests_per_second": app_metrics.requests_per_second
                }
            }
        except Exception as e:
            logger.error(
                "get_health_status_error",
                error=str(e),
                error_type=type(e).__name__
            )
            return {
                "status": "unhealthy",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }

# Глобальный экземпляр мониторинга
enhanced_monitoring = EnhancedMonitoring()