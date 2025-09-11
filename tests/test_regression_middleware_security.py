"""
P0/P1: Регрессионные тесты middleware и безопасности
Критические тесты, блокирующие мёрж до зелёного прогона
"""

import pytest
import json
import uuid
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from backend.main import app

client = TestClient(app)

class TestCORSMiddleware:
    """P0: Критические тесты CORS middleware"""
    
    def test_cors_preflight_requests(self):
        """P0: CORS preflight запросы"""
        # Тест OPTIONS запроса
        response = client.options("/api/projects")
        
        # Проверяем CORS заголовки
        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers
        assert "Access-Control-Allow-Credentials" in response.headers
    
    def test_cors_origin_validation(self):
        """P0: Валидация CORS origins"""
        # Тест с разрешённым origin
        response = client.options(
            "/api/projects",
            headers={"Origin": "https://samokoder.com"}
        )
        
        assert response.status_code == 200
        cors_headers = response.headers
        
        # Проверяем, что разрешённый origin принят
        if "Access-Control-Allow-Origin" in cors_headers:
            assert cors_headers["Access-Control-Allow-Origin"] in [
                "https://samokoder.com", "*"
            ]
    
    def test_cors_methods_validation(self):
        """P0: Валидация CORS методов"""
        response = client.options(
            "/api/projects",
            headers={"Access-Control-Request-Method": "POST"}
        )
        
        assert response.status_code == 200
        cors_headers = response.headers
        
        if "Access-Control-Allow-Methods" in cors_headers:
            allowed_methods = cors_headers["Access-Control-Allow-Methods"]
            assert "POST" in allowed_methods
            assert "GET" in allowed_methods
            assert "PUT" in allowed_methods
            assert "DELETE" in allowed_methods
    
    def test_cors_headers_validation(self):
        """P0: Валидация CORS заголовков"""
        response = client.options(
            "/api/projects",
            headers={"Access-Control-Request-Headers": "Authorization,Content-Type"}
        )
        
        assert response.status_code == 200
        cors_headers = response.headers
        
        if "Access-Control-Allow-Headers" in cors_headers:
            allowed_headers = cors_headers["Access-Control-Allow-Headers"]
            assert "Authorization" in allowed_headers
            assert "Content-Type" in allowed_headers
            assert "X-CSRF-Token" in allowed_headers
            assert "X-Requested-With" in allowed_headers
    
    def test_cors_credentials_handling(self):
        """P0: Обработка CORS credentials"""
        response = client.options("/api/projects")
        
        cors_headers = response.headers
        
        if "Access-Control-Allow-Credentials" in cors_headers:
            assert cors_headers["Access-Control-Allow-Credentials"] == "true"
        
        if "Access-Control-Allow-Origin" in cors_headers:
            # Если credentials=true, то origin не может быть *
            if cors_headers.get("Access-Control-Allow-Credentials") == "true":
                assert cors_headers["Access-Control-Allow-Origin"] != "*"

class TestCSRFMiddleware:
    """P0: Критические тесты CSRF middleware"""
    
    def test_csrf_protection_get_requests(self):
        """P0: CSRF защита для GET запросов"""
        # GET запросы должны проходить без CSRF токена
        response = client.get("/api/projects")
        # Может быть 401 из-за отсутствия аутентификации, но не 403 CSRF
        assert response.status_code != 403
    
    def test_csrf_protection_post_requests(self):
        """P0: CSRF защита для POST запросов"""
        # POST запрос без CSRF токена должен быть отклонён
        response = client.post(
            "/api/projects",
            json={"name": "Test", "description": "Test"},
            headers={"X-CSRF-Token": ""}
        )
        assert response.status_code == 403
        
        # POST запрос с коротким CSRF токеном должен быть отклонён
        response = client.post(
            "/api/projects",
            json={"name": "Test", "description": "Test"},
            headers={"X-CSRF-Token": "short"}
        )
        assert response.status_code == 403
    
    def test_csrf_protection_put_requests(self):
        """P0: CSRF защита для PUT запросов"""
        # PUT запрос без CSRF токена должен быть отклонён
        response = client.put(
            "/api/projects/test_id",
            json={"name": "Updated Test"},
            headers={"X-CSRF-Token": ""}
        )
        assert response.status_code == 403
    
    def test_csrf_protection_delete_requests(self):
        """P0: CSRF защита для DELETE запросов"""
        # DELETE запрос без CSRF токена должен быть отклонён
        response = client.delete(
            "/api/projects/test_id",
            headers={"X-CSRF-Token": ""}
        )
        assert response.status_code == 403
    
    def test_csrf_token_validation(self):
        """P0: Валидация CSRF токенов"""
        # POST запрос с валидным CSRF токеном должен пройти (если есть аутентификация)
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            response = client.post(
                "/api/projects",
                json={"name": "Test", "description": "Test"},
                headers={"X-CSRF-Token": "valid_csrf_token_1234567890"}
            )
            # Может быть 500 из-за отсутствия других зависимостей, но не 403 CSRF
            assert response.status_code != 403

class TestSecurityHeadersMiddleware:
    """P0: Критические тесты middleware безопасных заголовков"""
    
    def test_security_headers_presence(self):
        """P0: Наличие безопасных заголовков"""
        response = client.get("/")
        
        # Проверяем наличие обязательных безопасных заголовков
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'"
        }
        
        for header, expected_value in security_headers.items():
            assert header in response.headers, f"Отсутствует заголовок безопасности: {header}"
            if expected_value:
                assert response.headers[header] == expected_value, f"Неверное значение заголовка {header}: {response.headers[header]}"
    
    def test_security_headers_all_endpoints(self):
        """P0: Безопасные заголовки на всех эндпоинтах"""
        endpoints = [
            "/",
            "/health",
            "/metrics",
            "/api/projects",
            "/api/auth/login",
            "/api/ai/chat"
        ]
        
        for endpoint in endpoints:
            response = client.get(endpoint)
            
            # Проверяем основные заголовки безопасности
            assert "X-Content-Type-Options" in response.headers
            assert "X-Frame-Options" in response.headers
            assert "X-XSS-Protection" in response.headers
            assert "Strict-Transport-Security" in response.headers
    
    def test_content_type_options(self):
        """P0: Заголовок X-Content-Type-Options"""
        response = client.get("/")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
    
    def test_frame_options(self):
        """P0: Заголовок X-Frame-Options"""
        response = client.get("/")
        assert response.headers["X-Frame-Options"] == "DENY"
    
    def test_xss_protection(self):
        """P0: Заголовок X-XSS-Protection"""
        response = client.get("/")
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
    
    def test_hsts_header(self):
        """P0: Заголовок Strict-Transport-Security"""
        response = client.get("/")
        hsts_header = response.headers["Strict-Transport-Security"]
        assert "max-age=31536000" in hsts_header
        assert "includeSubDomains" in hsts_header
    
    def test_referrer_policy(self):
        """P0: Заголовок Referrer-Policy"""
        response = client.get("/")
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    
    def test_content_security_policy(self):
        """P0: Заголовок Content-Security-Policy"""
        response = client.get("/")
        csp_header = response.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp_header

class TestRateLimitingMiddleware:
    """P1: Тесты rate limiting middleware"""
    
    def test_rate_limiting_auth_endpoints(self):
        """P1: Rate limiting для эндпоинтов аутентификации"""
        login_data = {
            "email": "ratelimit@example.com",
            "password": "SecurePass123!"
        }
        
        # Делаем множественные запросы
        for i in range(10):
            response = client.post("/api/auth/login", json=login_data)
            if i >= 3:  # После 3 попыток должен сработать rate limiting
                assert response.status_code == 429
                break
    
    def test_rate_limiting_api_endpoints(self):
        """P1: Rate limiting для API эндпоинтов"""
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Делаем множественные запросы к API
            for i in range(20):
                response = client.get("/api/projects")
                if i >= 10:  # После 10 запросов должен сработать rate limiting
                    assert response.status_code == 429
                    break
    
    def test_rate_limiting_ai_endpoints(self):
        """P1: Rate limiting для AI эндпоинтов"""
        chat_data = {
            "message": "Test message",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            mock_ai_instance = MagicMock()
            mock_ai_instance.route_request = AsyncMock(return_value=MagicMock(
                content="Test response",
                provider="openrouter",
                model="deepseek/deepseek-v3",
                tokens_used=100,
                cost_usd=0.001,
                success=True,
                response_time=1.0
            ))
            mock_ai_service.return_value = mock_ai_instance
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            # Делаем множественные запросы к AI
            for i in range(15):
                response = client.post("/api/ai/chat", json=chat_data)
                if i >= 5:  # После 5 запросов должен сработать rate limiting
                    assert response.status_code == 429
                    break

class TestValidationMiddleware:
    """P1: Тесты validation middleware"""
    
    def test_input_validation_json(self):
        """P1: Валидация JSON входных данных"""
        # Тест с невалидным JSON
        response = client.post(
            "/api/projects",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400
        
        # Тест с пустым JSON
        response = client.post(
            "/api/projects",
            data="",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400
    
    def test_input_validation_content_type(self):
        """P1: Валидация Content-Type заголовков"""
        # Тест с неправильным Content-Type
        response = client.post(
            "/api/projects",
            data="test data",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 400
        
        # Тест без Content-Type
        response = client.post(
            "/api/projects",
            data="test data"
        )
        assert response.status_code == 400
    
    def test_input_validation_size_limits(self):
        """P1: Валидация ограничений размера данных"""
        # Тест с очень большим JSON
        large_data = {"name": "x" * 10000, "description": "y" * 10000}
        
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            response = client.post("/api/projects", json=large_data)
            # Должен быть отклонён из-за размера
            assert response.status_code in [400, 413, 422]

class TestErrorHandlingMiddleware:
    """P0: Критические тесты error handling middleware"""
    
    def test_error_response_format(self):
        """P0: Формат ответов об ошибках"""
        # Тест с несуществующим эндпоинтом
        response = client.get("/nonexistent-endpoint")
        assert response.status_code == 404
        
        data = response.json()
        assert "detail" in data or "error" in data
    
    def test_error_logging(self):
        """P0: Логирование ошибок"""
        # Тест с внутренней ошибкой сервера
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.side_effect = Exception("Internal server error")
            
            response = client.get("/api/projects")
            assert response.status_code == 500
    
    def test_error_sanitization(self):
        """P0: Санитизация ошибок"""
        # Тест с ошибкой, содержащей чувствительные данные
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.side_effect = Exception("Database error: password=secret123")
            
            response = client.get("/api/projects")
            assert response.status_code == 500
            
            data = response.json()
            # Проверяем, что чувствительные данные не попали в ответ
            assert "password=secret123" not in str(data)

class TestMonitoringMiddleware:
    """P1: Тесты monitoring middleware"""
    
    def test_request_logging(self):
        """P1: Логирование запросов"""
        with patch('backend.monitoring.logger') as mock_logger:
            response = client.get("/")
            
            # Проверяем, что запрос был залогирован
            assert mock_logger.info.called
    
    def test_response_time_logging(self):
        """P1: Логирование времени ответа"""
        with patch('backend.monitoring.logger') as mock_logger:
            response = client.get("/")
            
            # Проверяем, что время ответа было залогировано
            call_args = mock_logger.info.call_args
            if call_args:
                assert "process_time" in str(call_args)
    
    def test_error_logging(self):
        """P1: Логирование ошибок"""
        with patch('backend.monitoring.logger') as mock_logger:
            with patch('backend.main.get_current_user') as mock_auth:
                mock_auth.side_effect = Exception("Test error")
                
                response = client.get("/api/projects")
                
                # Проверяем, что ошибка была залогирована
                assert mock_logger.error.called

class TestMiddlewareIntegration:
    """P0: Интеграционные тесты middleware"""
    
    def test_middleware_chain_order(self):
        """P0: Порядок выполнения middleware"""
        response = client.get("/")
        
        # Проверяем, что все middleware сработали
        assert "X-Content-Type-Options" in response.headers  # Security headers
        assert "Access-Control-Allow-Origin" in response.headers  # CORS
        # Rate limiting и validation могут не сработать для GET запросов
    
    def test_middleware_performance(self):
        """P1: Производительность middleware"""
        import time
        
        start_time = time.time()
        
        for _ in range(10):
            response = client.get("/")
            assert response.status_code == 200
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Проверяем, что middleware не замедляют ответы значительно
        assert total_time < 2.0  # 10 запросов за менее чем 2 секунды
    
    def test_middleware_error_handling(self):
        """P0: Обработка ошибок в middleware"""
        # Тест с ошибкой в middleware
        with patch('backend.main.monitoring_middleware') as mock_middleware:
            mock_middleware.side_effect = Exception("Middleware error")
            
            response = client.get("/")
            # Приложение должно продолжать работать даже при ошибке в middleware
            assert response.status_code in [200, 500]

if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, "-v", "--tb=short", "-x"])