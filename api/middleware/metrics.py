"""Prometheus metrics middleware for Samokoder."""
from prometheus_client import Counter, Histogram, Gauge, Info
from typing import Callable
from fastapi import Request, Response
from time import time
import psutil
import os


# ==================== Application Info ====================
app_info = Info('samokoder_app', 'Samokoder application info')
app_info.info({
    'version': '1.0',
    'environment': os.getenv('ENVIRONMENT', 'development'),
})


# ==================== HTTP Metrics ====================
http_requests_total = Counter(
    'samokoder_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'samokoder_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=(0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0)
)

http_requests_in_progress = Gauge(
    'samokoder_http_requests_in_progress',
    'Number of HTTP requests in progress',
    ['method', 'endpoint']
)


# ==================== Business Metrics ====================
projects_created_total = Counter(
    'samokoder_projects_created_total',
    'Total number of projects created',
    ['user_tier']
)

projects_generation_duration_seconds = Histogram(
    'samokoder_projects_generation_duration_seconds',
    'Project generation duration in seconds',
    ['complexity'],
    buckets=(10, 30, 60, 120, 300, 600, 1200, 1800, 3600)
)

llm_requests_total = Counter(
    'samokoder_llm_requests_total',
    'Total LLM requests',
    ['provider', 'model', 'agent']
)

llm_tokens_consumed_total = Counter(
    'samokoder_llm_tokens_consumed_total',
    'Total LLM tokens consumed',
    ['provider', 'model', 'token_type']  # token_type: prompt, completion
)

llm_request_errors_total = Counter(
    'samokoder_llm_request_errors_total',
    'Total LLM request errors',
    ['provider', 'error_type']
)

llm_request_duration_seconds = Histogram(
    'samokoder_llm_request_duration_seconds',
    'LLM request duration in seconds',
    ['provider', 'model'],
    buckets=(0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0)
)


# ==================== Database Metrics ====================
db_connections_active = Gauge(
    'samokoder_db_connections_active',
    'Number of active database connections'
)

db_query_duration_seconds = Histogram(
    'samokoder_db_query_duration_seconds',
    'Database query duration in seconds',
    ['operation'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

db_errors_total = Counter(
    'samokoder_db_errors_total',
    'Total database errors',
    ['error_type']
)


# ==================== Rate Limiting Metrics ====================
rate_limit_hits_total = Counter(
    'samokoder_rate_limit_hits_total',
    'Total rate limit hits (429 responses)',
    ['endpoint', 'limit_type']
)


# ==================== System Metrics ====================
system_cpu_usage_percent = Gauge(
    'samokoder_system_cpu_usage_percent',
    'System CPU usage percentage'
)

system_memory_usage_bytes = Gauge(
    'samokoder_system_memory_usage_bytes',
    'System memory usage in bytes',
    ['type']  # type: used, available, total
)

system_disk_usage_bytes = Gauge(
    'samokoder_system_disk_usage_bytes',
    'System disk usage in bytes',
    ['path', 'type']  # type: used, free, total
)

docker_containers_running = Gauge(
    'samokoder_docker_containers_running',
    'Number of running Docker containers',
    ['managed_by']
)


# ==================== Authentication Metrics ====================
auth_attempts_total = Counter(
    'samokoder_auth_attempts_total',
    'Total authentication attempts',
    ['result']  # result: success, failure
)

active_users_total = Gauge(
    'samokoder_active_users_total',
    'Number of active users (last 24h)'
)


# ==================== Helper Functions ====================
def update_system_metrics():
    """Update system-level metrics (CPU, memory, disk)."""
    try:
        # CPU
        system_cpu_usage_percent.set(psutil.cpu_percent(interval=0.1))
        
        # Memory
        mem = psutil.virtual_memory()
        system_memory_usage_bytes.labels(type='used').set(mem.used)
        system_memory_usage_bytes.labels(type='available').set(mem.available)
        system_memory_usage_bytes.labels(type='total').set(mem.total)
        
        # Disk
        disk = psutil.disk_usage('/')
        system_disk_usage_bytes.labels(path='/', type='used').set(disk.used)
        system_disk_usage_bytes.labels(path='/', type='free').set(disk.free)
        system_disk_usage_bytes.labels(path='/', type='total').set(disk.total)
    except Exception as e:
        print(f"Error updating system metrics: {e}")


def track_http_request(method: str, endpoint: str, status: int, duration: float):
    """Track HTTP request metrics."""
    http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
    http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)


async def metrics_middleware(request: Request, call_next: Callable) -> Response:
    """Middleware to track HTTP request metrics."""
    method = request.method
    endpoint = request.url.path
    
    # Track request in progress
    http_requests_in_progress.labels(method=method, endpoint=endpoint).inc()
    
    # Time the request
    start_time = time()
    
    try:
        response = await call_next(request)
        duration = time() - start_time
        
        # Track metrics
        track_http_request(method, endpoint, response.status_code, duration)
        
        # Track rate limit hits
        if response.status_code == 429:
            rate_limit_hits_total.labels(
                endpoint=endpoint,
                limit_type='unknown'  # TODO: extract from response if available
            ).inc()
        
        return response
    finally:
        # Decrement in-progress counter
        http_requests_in_progress.labels(method=method, endpoint=endpoint).dec()
        
        # Update system metrics periodically (every 10th request)
        import random
        if random.randint(1, 10) == 1:
            update_system_metrics()
