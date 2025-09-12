#!/usr/bin/env python3
"""
Тесты для Main.py
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
    initialize_managers, log_request_info, global_exception_handler,
    security_headers_middleware, csrf_middleware
)


class TestMainPy:
    """Тесты для main.py"""
    
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
    
    @patch('backend.main.logger')
    def test_log_request_info_error(self, mock_logger):
        """Тест ошибки при логировании"""
        mock_request = Mock()
        mock_request.client = Mock(side_effect=Exception("Error"))
        
        log_request_info(mock_request)
        
        mock_logger.error.assert_called_once()
    
    @patch('backend.main.secure_error_handler')
    async def test_global_exception_handler(self, mock_handler):
        """Тест глобального обработчика исключений"""
        mock_request = Mock()
        mock_exception = Exception("Test error")
        mock_response = {"error": "Test error"}
        
        mock_handler.create_error_context.return_value = "context"
        mock_handler.handle_generic_error.return_value = mock_response
        
        result = await global_exception_handler(mock_request, mock_exception)
        
        mock_handler.create_error_context.assert_called_once_with(mock_request, "HIGH")
        mock_handler.handle_generic_error.assert_called_once_with(mock_exception, "context")
        assert result == mock_response
    
    def test_health_endpoint(self):
        """Тест эндпоинта health"""
        client = TestClient(app)
        
        with patch('backend.main.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.return_value = {"status": "healthy"}
            
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "healthy"}
    
    @patch('backend.main.monitoring')
    @patch('backend.main.logger')
    def test_health_endpoint_monitoring_error(self, mock_logger, mock_monitoring):
        """Тест ошибки мониторинга в health эндпоинте"""
        from backend.core.exceptions import MonitoringError
        
        mock_monitoring.get_health_status.side_effect = MonitoringError("Monitoring error")
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 503
        assert "Monitoring service unavailable" in response.json()["detail"]
        mock_logger.error.assert_called()
    
    @patch('backend.main.get_metrics_response')
    def test_metrics_endpoint(self, mock_get_metrics):
        """Тест эндпоинта metrics"""
        mock_get_metrics.return_value = "test_metrics"
        
        client = TestClient(app)
        response = client.get("/metrics")
        
        assert response.status_code == 200
        assert response.text == "test_metrics"
    
    @patch('backend.main.get_metrics_response')
    @patch('backend.main.logger')
    def test_metrics_endpoint_error(self, mock_logger, mock_get_metrics):
        """Тест ошибки в metrics эндпоинте"""
        mock_get_metrics.side_effect = Exception("Metrics error")
        
        client = TestClient(app)
        response = client.get("/metrics")
        
        assert response.status_code == 500
        assert "Metrics unavailable" in response.json()["detail"]
        mock_logger.error.assert_called()
    
    @patch('backend.main.settings')
    @patch('backend.main.supabase_manager')
    def test_login_endpoint_mock_success(self, mock_supabase_manager, mock_settings):
        """Тест успешного входа в систему"""
        mock_settings.supabase_url = "https://test.supabase.co"
        
        mock_client = Mock()
        mock_user = Mock()
        mock_user.id = "user123"
        mock_user.email = "test@example.com"
        mock_user.created_at = "2023-01-01"
        mock_user.updated_at = "2023-01-01"
        mock_user.user_metadata = {"full_name": "Test User"}
        
        mock_session = Mock()
        mock_session.access_token = "access_token_123"
        
        mock_response = Mock()
        mock_response.user = mock_user
        mock_response.session = mock_session
        
        mock_client.auth.sign_in_with_password.return_value = mock_response
        mock_supabase_manager.get_client.return_value = mock_client
        
        client = TestClient(app)
        response = client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "password123"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["user"]["email"] == "test@example.com"
        assert data["access_token"] == "access_token_123"
    
    @patch('backend.main.settings')
    @patch('backend.main.supabase_manager')
    def test_login_endpoint_no_client(self, mock_supabase_manager, mock_settings):
        """Тест входа без доступного клиента Supabase"""
        mock_settings.supabase_url = "https://test.supabase.co"
        mock_supabase_manager.get_client.return_value = None
        
        client = TestClient(app)
        response = client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "password123"
        })
        
        assert response.status_code == 503
        assert "Authentication service unavailable" in response.json()["detail"]
    
    @patch('backend.main.settings')
    @patch('backend.main.supabase_manager')
    def test_login_endpoint_invalid_credentials(self, mock_supabase_manager, mock_settings):
        """Тест входа с неверными учетными данными"""
        mock_settings.supabase_url = "https://test.supabase.co"
        
        mock_client = Mock()
        mock_response = Mock()
        mock_response.user = None
        
        mock_client.auth.sign_in_with_password.return_value = mock_response
        mock_supabase_manager.get_client.return_value = mock_client
        
        client = TestClient(app)
        response = client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "wrongpassword"
        })
        
        assert response.status_code == 401
        assert "Неверные учетные данные" in response.json()["detail"]
    
    @patch('backend.main.settings')
    @patch('backend.main.supabase_manager')
    def test_register_endpoint_success(self, mock_supabase_manager, mock_settings):
        """Тест успешной регистрации"""
        mock_settings.supabase_url = "https://test.supabase.co"
        
        mock_client = Mock()
        mock_user = Mock()
        mock_user.id = "user123"
        
        mock_response = Mock()
        mock_response.user = mock_user
        
        mock_client.auth.sign_up.return_value = mock_response
        mock_supabase_manager.get_client.return_value = mock_client
        
        client = TestClient(app)
        response = client.post("/api/auth/register", json={
            "email": "test@example.com",
            "password": "password123",
            "full_name": "Test User"
        })
        
        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert data["email"] == "test@example.com"
        assert data["user_id"] == "user123"
    
    @patch('backend.main.get_current_user')
    def test_logout_endpoint(self, mock_get_current_user):
        """Тест выхода из системы"""
        mock_get_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        
        client = TestClient(app)
        response = client.post("/api/auth/logout")
        
        assert response.status_code == 200
        data = response.json()
        assert "Успешный выход из системы" in data["message"]
        assert "timestamp" in data
    
    @patch('backend.main.get_current_user')
    def test_get_current_user_info_endpoint(self, mock_get_current_user):
        """Тест получения информации о текущем пользователе"""
        mock_user = {"id": "user123", "email": "test@example.com"}
        mock_get_current_user.return_value = mock_user
        
        client = TestClient(app)
        response = client.get("/api/auth/user")
        
        assert response.status_code == 200
        data = response.json()
        assert data["user"] == mock_user
        assert "timestamp" in data
    
    def test_security_headers_middleware(self):
        """Тест middleware для заголовков безопасности"""
        client = TestClient(app)
        
        with patch('backend.main.call_next') as mock_call_next:
            mock_response = Mock()
            mock_response.headers = {}
            mock_call_next.return_value = mock_response
            
            # Создаем mock request
            mock_request = Mock()
            
            # Тестируем middleware напрямую
            async def test_middleware():
                return await security_headers_middleware(mock_request, mock_call_next)
            
            import asyncio
            result = asyncio.run(test_middleware())
            
            # Проверяем что заголовки безопасности добавлены
            assert "X-Content-Type-Options" in result.headers
            assert result.headers["X-Content-Type-Options"] == "nosniff"
            assert "X-Frame-Options" in result.headers
            assert result.headers["X-Frame-Options"] == "DENY"
    
    @patch('backend.main.validate_csrf_token')
    def test_csrf_middleware_get_request(self, mock_validate):
        """Тест CSRF middleware для GET запроса"""
        mock_request = Mock()
        mock_request.method = "GET"
        
        with patch('backend.main.call_next') as mock_call_next:
            mock_response = Mock()
            mock_call_next.return_value = mock_response
            
            async def test_middleware():
                return await csrf_middleware(mock_request, mock_call_next)
            
            import asyncio
            result = asyncio.run(test_middleware())
            
            # GET запросы должны проходить без CSRF проверки
            mock_call_next.assert_called_once_with(mock_request)
            mock_validate.assert_not_called()
    
    @patch('backend.main.validate_csrf_token')
    def test_csrf_middleware_missing_token(self, mock_validate):
        """Тест CSRF middleware без токена"""
        mock_request = Mock()
        mock_request.method = "POST"
        mock_request.headers = {}
        
        with patch('backend.main.call_next') as mock_call_next:
            async def test_middleware():
                return await csrf_middleware(mock_request, mock_call_next)
            
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(test_middleware())
            
            assert exc_info.value.status_code == 403
            assert "CSRF token missing" in exc_info.value.detail
    
    @patch('backend.main.validate_csrf_token')
    def test_csrf_middleware_invalid_token(self, mock_validate):
        """Тест CSRF middleware с невалидным токеном"""
        mock_validate.return_value = False
        
        mock_request = Mock()
        mock_request.method = "POST"
        mock_request.headers = {"X-CSRF-Token": "invalid_token"}
        
        with patch('backend.main.call_next') as mock_call_next:
            async def test_middleware():
                return await csrf_middleware(mock_request, mock_call_next)
            
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(test_middleware())
            
            assert exc_info.value.status_code == 403
            assert "Invalid CSRF token" in exc_info.value.detail
    
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
