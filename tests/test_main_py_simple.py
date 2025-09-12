#!/usr/bin/env python3
"""
Упрощенные тесты для Main.py
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import HTTPException
import json
import time
import hmac
import hashlib
from datetime import datetime
from backend.main import (
    app, secure_error_handler, validate_csrf_token, 
    initialize_managers, log_request_info
)


class TestMainPySimple:
    """Упрощенные тесты для main.py"""
    
    def test_app_exists(self):
        """Тест существования FastAPI приложения"""
        assert app is not None
        assert app.title == "Samokoder Backend API"
        assert app.version == "1.0.0"
    
    def test_secure_error_handler_exists(self):
        """Тест существования обработчика ошибок"""
        assert secure_error_handler is not None
    
    @patch('backend.main.settings')
    def test_validate_csrf_token_valid(self, mock_settings):
        """Тест валидации валидного CSRF токена"""
        mock_settings.secret_key = "test_secret_key"
        
        # Создаем валидный токен
        timestamp = str(int(time.time()))
        signature = hmac.new(
            mock_settings.secret_key.encode(),
            timestamp.encode(),
            hashlib.sha256
        ).hexdigest()
        token = f"{timestamp}.{signature}"
        
        result = validate_csrf_token(token)
        assert result is True
    
    @patch('backend.main.settings')
    def test_validate_csrf_token_invalid(self, mock_settings):
        """Тест валидации невалидного CSRF токена"""
        mock_settings.secret_key = "test_secret_key"
        
        # Невалидный токен
        invalid_token = "invalid.token"
        
        result = validate_csrf_token(invalid_token)
        assert result is False
    
    @patch('backend.main.settings')
    def test_validate_csrf_token_empty(self, mock_settings):
        """Тест валидации пустого CSRF токена"""
        mock_settings.secret_key = "test_secret_key"
        
        result = validate_csrf_token("")
        assert result is False
        
        result = validate_csrf_token(None)
        assert result is False
    
    @patch('backend.main.settings')
    def test_validate_csrf_token_expired(self, mock_settings):
        """Тест валидации истекшего CSRF токена"""
        mock_settings.secret_key = "test_secret_key"
        
        # Создаем истекший токен (старше 1 часа)
        old_timestamp = str(int(time.time()) - 7200)  # 2 часа назад
        signature = hmac.new(
            mock_settings.secret_key.encode(),
            old_timestamp.encode(),
            hashlib.sha256
        ).hexdigest()
        token = f"{old_timestamp}.{signature}"
        
        result = validate_csrf_token(token)
        assert result is False
    
    @patch('backend.main.settings')
    def test_validate_csrf_token_no_secret(self, mock_settings):
        """Тест валидации CSRF токена без секретного ключа"""
        mock_settings.secret_key = None
        
        result = validate_csrf_token("any.token")
        assert result is False
    
    @patch('backend.main.settings')
    def test_validate_csrf_token_malformed(self, mock_settings):
        """Тест валидации некорректного формата CSRF токена"""
        mock_settings.secret_key = "test_secret_key"
        
        # Токен без точки
        result = validate_csrf_token("notoken")
        assert result is False
        
        # Токен с некорректным timestamp
        result = validate_csrf_token("notanumber.signature")
        assert result is False
    
    @patch('backend.main.supabase_manager')
    @patch('backend.main.connection_manager')
    @patch('backend.main.project_state_manager')
    async def test_initialize_managers_success(self, mock_project_manager, mock_connection_manager, mock_supabase_manager):
        """Тест успешной инициализации менеджеров"""
        mock_supabase_manager.initialize = AsyncMock()
        mock_connection_manager.initialize = AsyncMock()
        mock_project_manager.initialize = AsyncMock()
        
        await initialize_managers()
        
        mock_supabase_manager.initialize.assert_called_once()
        mock_connection_manager.initialize.assert_called_once()
        mock_project_manager.initialize.assert_called_once()
    
    @patch('backend.main.supabase_manager')
    @patch('backend.main.connection_manager')
    @patch('backend.main.project_state_manager')
    @patch('backend.main.logger')
    async def test_initialize_managers_configuration_error(self, mock_logger, mock_project_manager, mock_connection_manager, mock_supabase_manager):
        """Тест ошибки конфигурации при инициализации"""
        from backend.core.exceptions import ConfigurationError
        
        mock_supabase_manager.initialize = AsyncMock(side_effect=ConfigurationError("Config error"))
        
        with pytest.raises(ConfigurationError):
            await initialize_managers()
        
        mock_logger.error.assert_called()
    
    @patch('backend.main.supabase_manager')
    @patch('backend.main.connection_manager')
    @patch('backend.main.project_state_manager')
    @patch('backend.main.logger')
    async def test_initialize_managers_connection_error(self, mock_logger, mock_project_manager, mock_connection_manager, mock_supabase_manager):
        """Тест ошибки подключения при инициализации"""
        from backend.core.exceptions import ConnectionError
        
        mock_supabase_manager.initialize = AsyncMock()
        mock_connection_manager.initialize = AsyncMock(side_effect=ConnectionError("Connection error"))
        
        with pytest.raises(ConnectionError):
            await initialize_managers()
        
        mock_logger.error.assert_called()
    
    @patch('backend.main.supabase_manager')
    @patch('backend.main.connection_manager')
    @patch('backend.main.project_state_manager')
    @patch('backend.main.logger')
    async def test_initialize_managers_general_error(self, mock_logger, mock_project_manager, mock_connection_manager, mock_supabase_manager):
        """Тест общей ошибки при инициализации"""
        from backend.core.exceptions import ConfigurationError
        
        mock_supabase_manager.initialize = AsyncMock(side_effect=Exception("General error"))
        
        with pytest.raises(ConfigurationError):
            await initialize_managers()
        
        mock_logger.error.assert_called()
    
    @patch('backend.main.logger')
    def test_log_request_info_success(self, mock_logger):
        """Тест успешного логирования информации о запросе"""
        mock_request = Mock()
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {"user-agent": "test-browser"}
        mock_request.url.path = "/test"
        mock_request.method = "GET"
        
        log_request_info(mock_request)
        
        mock_logger.info.assert_called_once()
    
    @patch('backend.main.logger')
    def test_log_request_info_no_client(self, mock_logger):
        """Тест логирования без клиентской информации"""
        mock_request = Mock()
        mock_request.client = None
        mock_request.headers = {"user-agent": "test-browser"}
        mock_request.url.path = "/test"
        mock_request.method = "GET"
        
        log_request_info(mock_request)
        
        mock_logger.info.assert_called_once()
    
    
    def test_app_includes_routers(self):
        """Тест что приложение включает все роутеры"""
        # Проверяем что роутеры включены (это проверяется через наличие эндпоинтов)
        client = TestClient(app)
        
        # Проверяем основные эндпоинты
        response = client.get("/docs")  # Swagger docs
        assert response.status_code == 200
        
        response = client.get("/redoc")  # ReDoc docs
        assert response.status_code == 200
    
    def test_cors_configuration(self):
        """Тест конфигурации CORS"""
        # Проверяем что CORS middleware добавлен
        # Это проверяется через наличие CORS заголовков в ответе
        client = TestClient(app)
        response = client.options("/health")
        
        # OPTIONS запрос должен обрабатываться CORS middleware
        assert response.status_code in [200, 405]  # 405 если OPTIONS не поддерживается
    
    def test_app_title_and_version(self):
        """Тест заголовка и версии приложения"""
        assert app.title == "Samokoder Backend API"
        assert app.description == "AI-платформа для создания full-stack приложений"
        assert app.version == "1.0.0"
        assert app.docs_url == "/docs"
        assert app.redoc_url == "/redoc"
    
    def test_health_endpoint_get(self):
        """Тест GET запроса к health эндпоинту"""
        client = TestClient(app)
        
        with patch('backend.main.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.return_value = {"status": "healthy"}
            
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "healthy"}
    
    def test_metrics_endpoint_get(self):
        """Тест GET запроса к metrics эндпоинту"""
        client = TestClient(app)
        
        with patch('backend.main.get_metrics_response') as mock_get_metrics:
            mock_get_metrics.return_value = "test_metrics"
            
            response = client.get("/metrics")
            assert response.status_code == 200
            assert response.text == '"test_metrics"'  # FastAPI возвращает JSON строку
    
    def test_app_has_middleware(self):
        """Тест что приложение имеет middleware"""
        # Проверяем что middleware добавлены
        assert len(app.user_middleware) > 0
    
    def test_app_has_exception_handler(self):
        """Тест что приложение имеет обработчик исключений"""
        # Проверяем что глобальный обработчик исключений зарегистрирован
        assert app.exception_handlers.get(Exception) is not None
    
    def test_csrf_token_format(self):
        """Тест формата CSRF токена"""
        # Тестируем что токен должен содержать точку
        with patch('backend.main.settings') as mock_settings:
            mock_settings.secret_key = "test_secret"
            
            # Валидный формат
            timestamp = str(int(time.time()))
            signature = "test_signature"
            valid_token = f"{timestamp}.{signature}"
            
            # Проверяем что функция пытается парсить токен
            # (результат будет False из-за неверной подписи, но не из-за формата)
            result = validate_csrf_token(valid_token)
            assert result is False  # False из-за неверной подписи, но не ошибка формата
    
    def test_allowed_origins_configuration(self):
        """Тест конфигурации разрешенных origins"""
        # Проверяем что CORS настроен с правильными origins
        # Это проверяется через наличие CORS middleware
        assert len(app.user_middleware) > 0
        
        # Проверяем что есть CORS middleware
        cors_middleware_exists = any(
            middleware.cls.__name__ == "CORSMiddleware" 
            for middleware in app.user_middleware
        )
        assert cors_middleware_exists
    
    def test_security_headers_present(self):
        """Тест наличия middleware для заголовков безопасности"""
        # Проверяем что есть middleware для заголовков безопасности
        # Это проверяется через наличие custom middleware
        middleware_names = [middleware.cls.__name__ for middleware in app.user_middleware]
        
        # Должен быть middleware для безопасности (не CORS)
        non_cors_middleware = [
            name for name in middleware_names 
            if name != "CORSMiddleware"
        ]
        assert len(non_cors_middleware) > 0
    
    def test_app_routes_exist(self):
        """Тест что основные маршруты существуют"""
        # Проверяем что основные маршруты зарегистрированы
        route_paths = [route.path for route in app.routes]
        
        # Основные маршруты должны существовать
        expected_routes = ["/health", "/metrics", "/docs", "/redoc"]
        for route in expected_routes:
            assert route in route_paths
    
    def test_app_startup_shutdown_events(self):
        """Тест событий startup и shutdown"""
        # Проверяем что события startup и shutdown зарегистрированы
        # Это проверяется через наличие функций в модуле
        import backend.main
        
        assert hasattr(backend.main, 'startup_event')
        assert hasattr(backend.main, 'shutdown_event')
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        # Проверяем что все необходимые импорты доступны
        import backend.main
        
        # Основные компоненты должны быть импортированы
        assert hasattr(backend.main, 'app')
        assert hasattr(backend.main, 'secure_error_handler')
        assert hasattr(backend.main, 'validate_csrf_token')
        assert hasattr(backend.main, 'initialize_managers')
        assert hasattr(backend.main, 'log_request_info')
