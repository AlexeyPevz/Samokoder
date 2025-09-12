#!/usr/bin/env python3
"""
Тесты для Monitoring
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime, timedelta
import time
from backend.monitoring import (
    MonitoringService, 
    get_monitoring, 
    monitoring_middleware,
    get_metrics, 
    get_metrics_response,
    check_database_health,
    check_ai_providers_health,
    check_external_services_health,
    log_user_action,
    log_security_event,
    log_performance_metric
)


class TestMonitoringService:
    """Тесты для MonitoringService"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        with patch('backend.monitoring.settings') as mock_settings:
            mock_settings.sentry_dsn = None
            mock_settings.environment = "test"
            self.monitoring = MonitoringService()
    
    def test_init(self):
        """Тест инициализации MonitoringService"""
        assert isinstance(self.monitoring.start_time, datetime)
        assert self.monitoring.request_count == 0
        assert self.monitoring.error_count == 0
        assert self.monitoring.active_connections == 0
    
    @patch('backend.monitoring.settings')
    @patch('backend.monitoring.sentry_sdk')
    def test_init_sentry_with_dsn(self, mock_sentry, mock_settings):
        """Тест инициализации Sentry с DSN"""
        mock_settings.sentry_dsn = "https://test@sentry.io/123"
        mock_settings.environment = "test"
        
        monitoring = MonitoringService()
        
        mock_sentry.init.assert_called_once()
        call_args = mock_sentry.init.call_args
        assert call_args[1]['dsn'] == "https://test@sentry.io/123"
        assert call_args[1]['environment'] == "test"
    
    @patch('backend.monitoring.settings')
    def test_init_sentry_without_dsn(self, mock_settings):
        """Тест инициализации Sentry без DSN"""
        mock_settings.sentry_dsn = None
        
        monitoring = MonitoringService()
        
        # Должен инициализироваться без ошибок
        assert monitoring.request_count == 0
    
    @patch('backend.monitoring.REQUEST_COUNT')
    @patch('backend.monitoring.REQUEST_DURATION')
    @patch('backend.monitoring.logger')
    def test_log_request_success(self, mock_logger, mock_duration, mock_count):
        """Тест логирования успешного запроса"""
        method = "GET"
        endpoint = "/api/test"
        status_code = 200
        duration = 0.5
        
        self.monitoring.log_request(method, endpoint, status_code, duration)
        
        assert self.monitoring.request_count == 1
        mock_count.labels.assert_called_once_with(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        )
        mock_count.labels.return_value.inc.assert_called_once()
        mock_duration.labels.assert_called_once_with(
            method=method,
            endpoint=endpoint
        )
        mock_duration.labels.return_value.observe.assert_called_once_with(duration)
        mock_logger.info.assert_called_once()
    
    @patch('backend.monitoring.REQUEST_COUNT')
    @patch('backend.monitoring.REQUEST_DURATION')
    @patch('backend.monitoring.logger')
    def test_log_request_error(self, mock_logger, mock_duration, mock_count):
        """Тест логирования запроса с ошибкой"""
        method = "POST"
        endpoint = "/api/error"
        status_code = 500
        duration = 1.0
        
        self.monitoring.log_request(method, endpoint, status_code, duration)
        
        assert self.monitoring.request_count == 1
        assert self.monitoring.error_count == 1
        mock_logger.info.assert_called_once()
        mock_logger.error.assert_called_once()
    
    @patch('backend.monitoring.AI_REQUESTS')
    @patch('backend.monitoring.AI_TOKENS')
    @patch('backend.monitoring.AI_COST')
    @patch('backend.monitoring.logger')
    def test_log_ai_request_success(self, mock_logger, mock_cost, mock_tokens, mock_requests):
        """Тест логирования успешного AI запроса"""
        provider = "openai"
        model = "gpt-4"
        tokens = 100
        cost = 0.05
        success = True
        
        self.monitoring.log_ai_request(provider, model, tokens, cost, success)
        
        mock_requests.labels.assert_called_once_with(
            provider=provider,
            model=model,
            status="success"
        )
        mock_tokens.labels.assert_called_once_with(
            provider=provider,
            model=model
        )
        mock_cost.labels.assert_called_once_with(
            provider=provider,
            model=model
        )
        mock_logger.info.assert_called_once()
    
    @patch('backend.monitoring.AI_REQUESTS')
    @patch('backend.monitoring.AI_TOKENS')
    @patch('backend.monitoring.AI_COST')
    @patch('backend.monitoring.logger')
    def test_log_ai_request_error(self, mock_logger, mock_cost, mock_tokens, mock_requests):
        """Тест логирования неуспешного AI запроса"""
        provider = "anthropic"
        model = "claude-3"
        tokens = 0
        cost = 0.0
        success = False
        
        self.monitoring.log_ai_request(provider, model, tokens, cost, success)
        
        mock_requests.labels.assert_called_once_with(
            provider=provider,
            model=model,
            status="error"
        )
        # Токены и стоимость не должны обновляться при ошибке
        mock_tokens.labels.assert_not_called()
        mock_cost.labels.assert_not_called()
        mock_logger.info.assert_called_once()
    
    @patch('backend.monitoring.PROJECT_CREATIONS')
    @patch('backend.monitoring.logger')
    def test_log_project_creation(self, mock_logger, mock_creations):
        """Тест логирования создания проекта"""
        user_id = "user123"
        project_id = "project456"
        
        self.monitoring.log_project_creation(user_id, project_id)
        
        mock_creations.labels.assert_called_once_with(user_id=user_id)
        mock_creations.labels.return_value.inc.assert_called_once()
        mock_logger.info.assert_called_once()
    
    @patch('backend.monitoring.PROJECT_EXPORTS')
    @patch('backend.monitoring.logger')
    def test_log_project_export(self, mock_logger, mock_exports):
        """Тест логирования экспорта проекта"""
        user_id = "user123"
        project_id = "project456"
        
        self.monitoring.log_project_export(user_id, project_id)
        
        mock_exports.labels.assert_called_once_with(user_id=user_id)
        mock_exports.labels.return_value.inc.assert_called_once()
        mock_logger.info.assert_called_once()
    
    @patch('backend.monitoring.settings')
    @patch('backend.monitoring.sentry_sdk')
    @patch('backend.monitoring.logger')
    def test_log_error_with_sentry(self, mock_logger, mock_sentry, mock_settings):
        """Тест логирования ошибки с Sentry"""
        mock_settings.sentry_dsn = "https://test@sentry.io/123"
        error = Exception("Test error")
        context = {"key": "value"}
        
        self.monitoring.log_error(error, context)
        
        assert self.monitoring.error_count == 1
        mock_logger.error.assert_called_once()
        mock_sentry.push_scope.assert_called_once()
        mock_sentry.capture_exception.assert_called_once_with(error)
    
    @patch('backend.monitoring.settings')
    @patch('backend.monitoring.sentry_sdk')
    @patch('backend.monitoring.logger')
    def test_log_error_without_sentry(self, mock_logger, mock_sentry, mock_settings):
        """Тест логирования ошибки без Sentry"""
        mock_settings.sentry_dsn = None
        error = Exception("Test error")
        
        self.monitoring.log_error(error)
        
        assert self.monitoring.error_count == 1
        mock_logger.error.assert_called_once()
        mock_sentry.capture_exception.assert_not_called()
    
    def test_get_health_status(self):
        """Тест получения статуса здоровья"""
        # Устанавливаем начальное время
        self.monitoring.start_time = datetime.now() - timedelta(seconds=3600)
        self.monitoring.request_count = 100
        self.monitoring.error_count = 5
        self.monitoring.active_connections = 3
        
        with patch('backend.monitoring.settings') as mock_settings:
            mock_settings.environment = "test"
            
            status = self.monitoring.get_health_status()
            
            assert status["status"] == "healthy"
            assert "timestamp" in status
            assert status["uptime"] > 0
            assert status["uptime_seconds"] > 0
            assert "uptime_human" in status
            assert status["request_count"] == 100
            assert status["error_count"] == 5
            assert status["error_rate"] == 5.0  # 5/100 * 100
            assert status["active_connections"] == 3
            assert status["environment"] == "test"
            assert status["version"] == "1.0.0"
            assert "services" in status
    
    def test_get_health_status_no_requests(self):
        """Тест получения статуса здоровья без запросов"""
        status = self.monitoring.get_health_status()
        
        assert status["request_count"] == 0
        assert status["error_count"] == 0
        assert status["error_rate"] == 0
    
    def test_format_uptime_seconds(self):
        """Тест форматирования времени - секунды"""
        uptime = self.monitoring._format_uptime(45.5)
        assert uptime == "45s"
    
    def test_format_uptime_minutes(self):
        """Тест форматирования времени - минуты"""
        uptime = self.monitoring._format_uptime(125.5)
        assert uptime == "2m 5s"
    
    def test_format_uptime_hours(self):
        """Тест форматирования времени - часы"""
        uptime = self.monitoring._format_uptime(3661.5)
        assert uptime == "1h 1m 1s"
    
    def test_format_uptime_days(self):
        """Тест форматирования времени - дни"""
        uptime = self.monitoring._format_uptime(90061.5)
        assert uptime == "1d 1h 1m 1s"
    
    @pytest.mark.asyncio
    async def test_track_connection(self):
        """Тест отслеживания соединений"""
        with patch('backend.monitoring.ACTIVE_CONNECTIONS') as mock_connections:
            async with self.monitoring.track_connection():
                assert self.monitoring.active_connections == 1
                mock_connections.set.assert_called_with(1)
            
            assert self.monitoring.active_connections == 0
            assert mock_connections.set.call_count == 2
    
    @pytest.mark.asyncio
    async def test_track_connection_with_exception(self):
        """Тест отслеживания соединений с исключением"""
        with patch('backend.monitoring.ACTIVE_CONNECTIONS') as mock_connections:
            try:
                async with self.monitoring.track_connection():
                    assert self.monitoring.active_connections == 1
                    raise Exception("Test error")
            except Exception:
                pass
            
            assert self.monitoring.active_connections == 0


class TestMonitoringGlobalFunctions:
    """Тесты для глобальных функций мониторинга"""
    
    def test_get_monitoring(self):
        """Тест получения экземпляра мониторинга"""
        monitoring = get_monitoring()
        assert isinstance(monitoring, MonitoringService)
    
    @pytest.mark.asyncio
    async def test_monitoring_middleware_success(self):
        """Тест middleware мониторинга - успешный запрос"""
        request = Mock()
        request.method = "GET"
        request.url.path = "/api/test"
        request.query_params = {}
        request.headers = {}
        
        response = Mock()
        response.status_code = 200
        
        async def mock_call_next(req):
            return response
        
        with patch('backend.monitoring.time.time', side_effect=[0, 0.5]):
            result = await monitoring_middleware(request, mock_call_next)
            
            assert result == response
    
    @pytest.mark.asyncio
    async def test_monitoring_middleware_error(self):
        """Тест middleware мониторинга - ошибка"""
        request = Mock()
        request.method = "POST"
        request.url.path = "/api/error"
        request.query_params = {"param": "value"}
        request.headers = {"Authorization": "Bearer token"}
        
        async def mock_call_next(req):
            raise Exception("Test error")
        
        with patch('backend.monitoring.time.time', side_effect=[0, 0.3]):
            with pytest.raises(Exception, match="Test error"):
                await monitoring_middleware(request, mock_call_next)
    
    @patch('backend.monitoring.generate_latest')
    def test_get_metrics(self, mock_generate):
        """Тест получения метрик"""
        mock_generate.return_value = b"test_metrics"
        
        result = get_metrics()
        
        assert result == b"test_metrics"
        mock_generate.assert_called_once()
    
    @patch('backend.monitoring.get_metrics')
    def test_get_metrics_response(self, mock_get_metrics):
        """Тест получения HTTP ответа с метриками"""
        mock_get_metrics.return_value = b"test_metrics"
        
        response = get_metrics_response()
        
        assert response.body == b"test_metrics"
        assert response.media_type == "text/plain; version=0.0.4; charset=utf-8"
    
    @pytest.mark.asyncio
    async def test_check_database_health_success(self):
        """Тест проверки здоровья базы данных - успех"""
        result = await check_database_health()
        
        assert result["status"] == "healthy"
        assert "response_time" in result
        assert result["error"] is None
    
    @pytest.mark.asyncio
    async def test_check_ai_providers_health(self):
        """Тест проверки здоровья AI провайдеров"""
        result = await check_ai_providers_health()
        
        assert "openrouter" in result
        assert "openai" in result
        assert "anthropic" in result
        assert "groq" in result
        
        for provider, status in result.items():
            assert status["status"] == "healthy"
            assert "response_time" in status
    
    @pytest.mark.asyncio
    async def test_check_external_services_health(self):
        """Тест проверки внешних сервисов"""
        result = await check_external_services_health()
        
        assert "supabase" in result
        assert "ai_providers" in result
        assert result["supabase"]["status"] == "healthy"
        assert "openrouter" in result["ai_providers"]
    
    @patch('backend.monitoring.logger')
    def test_log_user_action(self, mock_logger):
        """Тест логирования действий пользователя"""
        user_id = "user123"
        action = "login"
        details = {"ip": "192.168.1.1"}
        
        log_user_action(user_id, action, details)
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[1]
        assert call_args["user_id"] == user_id
        assert call_args["action"] == action
        assert call_args["details"] == details
    
    @patch('backend.monitoring.logger')
    def test_log_security_event(self, mock_logger):
        """Тест логирования событий безопасности"""
        event_type = "failed_login"
        user_id = "user123"
        details = {"ip": "192.168.1.1", "attempts": 3}
        
        log_security_event(event_type, user_id, details)
        
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[1]
        assert call_args["event_type"] == event_type
        assert call_args["user_id"] == user_id
        assert call_args["details"] == details
    
    @patch('backend.monitoring.logger')
    def test_log_performance_metric(self, mock_logger):
        """Тест логирования метрик производительности"""
        metric_name = "response_time"
        value = 0.5
        unit = "seconds"
        
        log_performance_metric(metric_name, value, unit)
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[1]
        assert call_args["metric_name"] == metric_name
        assert call_args["value"] == value
        assert call_args["unit"] == unit
    
    @patch('backend.monitoring.logger')
    def test_log_performance_metric_default_unit(self, mock_logger):
        """Тест логирования метрик производительности с единицей по умолчанию"""
        metric_name = "cpu_usage"
        value = 75.5
        
        log_performance_metric(metric_name, value)
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[1]
        assert call_args["metric_name"] == metric_name
        assert call_args["value"] == value
        assert call_args["unit"] == "seconds"