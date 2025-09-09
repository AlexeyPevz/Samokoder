"""
Production мониторинг и логирование
Sentry интеграция, метрики, health checks
"""

import time
import logging
import structlog
from datetime import datetime
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.httpx import HttpxIntegration
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from fastapi.responses import PlainTextResponse

from config.settings import settings

# Настройка структурированного логирования
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

# Получаем логгер
logger = structlog.get_logger()

# Prometheus метрики
REQUEST_COUNT = Counter(
    'api_requests_total', 
    'Total API requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'api_request_duration_seconds',
    'API request duration in seconds',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'api_active_connections',
    'Number of active connections'
)

AI_REQUESTS = Counter(
    'ai_requests_total',
    'Total AI requests',
    ['provider', 'model', 'status']
)

AI_TOKENS = Counter(
    'ai_tokens_total',
    'Total AI tokens used',
    ['provider', 'model']
)

AI_COST = Counter(
    'ai_cost_usd_total',
    'Total AI cost in USD',
    ['provider', 'model']
)

PROJECT_CREATIONS = Counter(
    'projects_created_total',
    'Total projects created',
    ['user_id']
)

PROJECT_EXPORTS = Counter(
    'projects_exported_total',
    'Total projects exported',
    ['user_id']
)

class MonitoringService:
    """Сервис для мониторинга и логирования"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.request_count = 0
        self.error_count = 0
        self.active_connections = 0
        
        # Инициализация Sentry
        self._init_sentry()
    
    def _init_sentry(self):
        """Инициализация Sentry для отслеживания ошибок"""
        
        if settings.sentry_dsn:
            sentry_sdk.init(
                dsn=settings.sentry_dsn,
                integrations=[
                    FastApiIntegration(auto_enabling_instrumentations=True),
                    SqlalchemyIntegration(),
                    HttpxIntegration(),
                ],
                traces_sample_rate=0.1,  # 10% трассировка
                profiles_sample_rate=0.1,  # 10% профилирование
                environment=settings.environment,
                release=f"samokoder@{settings.environment}",
            )
            logger.info("Sentry initialized successfully")
        else:
            logger.warning("Sentry DSN not configured, error tracking disabled")
    
    def log_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Логирование HTTP запроса"""
        
        self.request_count += 1
        
        # Обновляем метрики
        REQUEST_COUNT.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        # Логируем запрос
        logger.info(
            "api_request",
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            duration=duration,
            request_count=self.request_count
        )
        
        # Логируем ошибки
        if status_code >= 400:
            self.error_count += 1
            logger.error(
                "api_error",
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                duration=duration,
                error_count=self.error_count
            )
    
    def log_ai_request(self, provider: str, model: str, tokens: int, cost: float, success: bool):
        """Логирование AI запроса"""
        
        status = "success" if success else "error"
        
        AI_REQUESTS.labels(
            provider=provider,
            model=model,
            status=status
        ).inc()
        
        if success:
            AI_TOKENS.labels(
                provider=provider,
                model=model
            ).inc(tokens)
            
            AI_COST.labels(
                provider=provider,
                model=model
            ).inc(cost)
        
        logger.info(
            "ai_request",
            provider=provider,
            model=model,
            tokens=tokens,
            cost=cost,
            success=success
        )
    
    def log_project_creation(self, user_id: str, project_id: str):
        """Логирование создания проекта"""
        
        PROJECT_CREATIONS.labels(user_id=user_id).inc()
        
        logger.info(
            "project_created",
            user_id=user_id,
            project_id=project_id
        )
    
    def log_project_export(self, user_id: str, project_id: str):
        """Логирование экспорта проекта"""
        
        PROJECT_EXPORTS.labels(user_id=user_id).inc()
        
        logger.info(
            "project_exported",
            user_id=user_id,
            project_id=project_id
        )
    
    def log_error(self, error: Exception, context: Dict[str, Any] = None):
        """Логирование ошибки"""
        
        self.error_count += 1
        
        logger.error(
            "application_error",
            error=str(error),
            error_type=type(error).__name__,
            context=context or {},
            error_count=self.error_count,
            exc_info=True
        )
        
        # Отправляем в Sentry
        if settings.sentry_dsn:
            with sentry_sdk.push_scope() as scope:
                if context:
                    for key, value in context.items():
                        scope.set_extra(key, value)
                sentry_sdk.capture_exception(error)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Получение статуса здоровья системы"""
        
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": uptime,
            "uptime_human": self._format_uptime(uptime),
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": (self.error_count / self.request_count * 100) if self.request_count > 0 else 0,
            "active_connections": self.active_connections,
            "environment": settings.environment,
            "version": "1.0.0"
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Форматирование времени работы"""
        
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {secs}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
    
    @asynccontextmanager
    async def track_connection(self):
        """Контекстный менеджер для отслеживания активных соединений"""
        
        self.active_connections += 1
        ACTIVE_CONNECTIONS.set(self.active_connections)
        
        try:
            yield
        finally:
            self.active_connections = max(0, self.active_connections - 1)
            ACTIVE_CONNECTIONS.set(self.active_connections)

# Глобальный экземпляр мониторинга
monitoring = MonitoringService()

def get_monitoring() -> MonitoringService:
    """Получение экземпляра мониторинга"""
    return monitoring

async def monitoring_middleware(request: Request, call_next):
    """Middleware для мониторинга запросов"""
    
    start_time = time.time()
    
    # Отслеживаем активные соединения
    async with monitoring.track_connection():
        try:
            response = await call_next(request)
            
            # Логируем успешный запрос
            duration = time.time() - start_time
            monitoring.log_request(
                method=request.method,
                endpoint=request.url.path,
                status_code=response.status_code,
                duration=duration
            )
            
            return response
            
        except Exception as e:
            # Логируем ошибку
            duration = time.time() - start_time
            monitoring.log_error(e, {
                "method": request.method,
                "endpoint": request.url.path,
                "duration": duration,
                "query_params": dict(request.query_params),
                "headers": dict(request.headers)
            })
            
            # Возвращаем ошибку
            raise

def get_metrics() -> str:
    """Получение метрик Prometheus"""
    return generate_latest()

def get_metrics_response() -> Response:
    """HTTP ответ с метриками Prometheus"""
    return PlainTextResponse(
        get_metrics(),
        media_type=CONTENT_TYPE_LATEST
    )

# Health check функции
async def check_database_health() -> Dict[str, Any]:
    """Проверка здоровья базы данных"""
    
    try:
        # Здесь будет проверка подключения к Supabase
        # Пока возвращаем mock данные
        return {
            "status": "healthy",
            "response_time": 0.001,
            "error": None
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "response_time": 0.0,
            "error": str(e)
        }

async def check_ai_providers_health() -> Dict[str, Any]:
    """Проверка здоровья AI провайдеров"""
    
    # Здесь будет проверка доступности AI провайдеров
    # Пока возвращаем mock данные
    return {
        "openrouter": {"status": "healthy", "response_time": 0.1},
        "openai": {"status": "healthy", "response_time": 0.2},
        "anthropic": {"status": "healthy", "response_time": 0.15},
        "groq": {"status": "healthy", "response_time": 0.05}
    }

async def check_external_services_health() -> Dict[str, Any]:
    """Проверка внешних сервисов"""
    
    return {
        "supabase": await check_database_health(),
        "ai_providers": await check_ai_providers_health()
    }

# Утилиты для логирования
def log_user_action(user_id: str, action: str, details: Dict[str, Any] = None):
    """Логирование действий пользователя"""
    
    logger.info(
        "user_action",
        user_id=user_id,
        action=action,
        details=details or {}
    )

def log_security_event(event_type: str, user_id: str = None, details: Dict[str, Any] = None):
    """Логирование событий безопасности"""
    
    logger.warning(
        "security_event",
        event_type=event_type,
        user_id=user_id,
        details=details or {}
    )

def log_performance_metric(metric_name: str, value: float, unit: str = "seconds"):
    """Логирование метрик производительности"""
    
    logger.info(
        "performance_metric",
        metric_name=metric_name,
        value=value,
        unit=unit
    )