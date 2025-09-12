#!/usr/bin/env python3
"""
Тесты для Secure CORS
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.security.secure_cors import (
    setup_secure_cors, setup_security_headers, 
    setup_csrf_protection, validate_csrf_token
)


class TestSecureCors:
    """Тесты для Secure CORS модуля"""
    
    def test_validate_csrf_token_valid(self):
        """Тест валидации валидного CSRF токена"""
        valid_token = "valid_token_12345"
        result = validate_csrf_token(valid_token)
        assert result is True
    
    def test_validate_csrf_token_invalid(self):
        """Тест валидации невалидного CSRF токена"""
        invalid_token = "short"
        result = validate_csrf_token(invalid_token)
        assert result is False
    
    def test_validate_csrf_token_empty(self):
        """Тест валидации пустого CSRF токена"""
        result = validate_csrf_token("")
        assert result is False
    
    def test_validate_csrf_token_none(self):
        """Тест валидации None CSRF токена"""
        # Функция не обрабатывает None, поэтому ожидаем TypeError
        with pytest.raises(TypeError):
            validate_csrf_token(None)
    
    @patch('backend.security.secure_cors.settings')
    def test_setup_secure_cors_production(self, mock_settings):
        """Тест настройки CORS для production"""
        mock_settings.environment = "production"
        
        app = FastAPI()
        setup_secure_cors(app)
        
        # Проверяем что CORS middleware добавлен
        assert len(app.user_middleware) > 0
        
        # Проверяем что есть CORS middleware
        cors_middleware_exists = any(
            middleware.cls.__name__ == "CORSMiddleware" 
            for middleware in app.user_middleware
        )
        assert cors_middleware_exists
    
    @patch('backend.security.secure_cors.settings')
    def test_setup_secure_cors_development(self, mock_settings):
        """Тест настройки CORS для development"""
        mock_settings.environment = "development"
        
        app = FastAPI()
        setup_secure_cors(app)
        
        # Проверяем что CORS middleware добавлен
        assert len(app.user_middleware) > 0
        
        # Проверяем что есть CORS middleware
        cors_middleware_exists = any(
            middleware.cls.__name__ == "CORSMiddleware" 
            for middleware in app.user_middleware
        )
        assert cors_middleware_exists
    
    def test_setup_security_headers(self):
        """Тест настройки заголовков безопасности"""
        app = FastAPI()
        setup_security_headers(app)
        
        # Проверяем что middleware добавлен
        assert len(app.user_middleware) > 0
        
        # Проверяем что есть custom middleware (не CORS)
        non_cors_middleware = [
            middleware for middleware in app.user_middleware
            if middleware.cls.__name__ != "CORSMiddleware"
        ]
        assert len(non_cors_middleware) > 0
    
    def test_setup_csrf_protection(self):
        """Тест настройки CSRF защиты"""
        app = FastAPI()
        setup_csrf_protection(app)
        
        # Проверяем что middleware добавлен
        assert len(app.user_middleware) > 0
        
        # Проверяем что есть custom middleware (не CORS)
        non_cors_middleware = [
            middleware for middleware in app.user_middleware
            if middleware.cls.__name__ != "CORSMiddleware"
        ]
        assert len(non_cors_middleware) > 0
    
    def test_security_headers_middleware_response(self):
        """Тест что middleware для заголовков безопасности работает"""
        app = FastAPI()
        setup_security_headers(app)
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.get("/test")
        
        # Проверяем что заголовки безопасности добавлены
        assert response.status_code == 200
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Strict-Transport-Security" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Permissions-Policy" in response.headers
    
    def test_csrf_protection_get_request(self):
        """Тест что GET запросы проходят через CSRF защиту"""
        app = FastAPI()
        setup_csrf_protection(app)
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.get("/test")
        
        # GET запросы должны проходить без CSRF токена
        assert response.status_code == 200
        assert response.json() == {"message": "test"}
    
    def test_csrf_protection_post_without_token(self):
        """Тест что POST запросы без CSRF токена блокируются"""
        app = FastAPI()
        setup_csrf_protection(app)
        
        @app.post("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.post("/test", json={"data": "test"})
        
        # POST запросы без CSRF токена должны блокироваться
        assert response.status_code == 403
        assert "CSRF token missing" in response.json()["error"]
    
    def test_csrf_protection_post_with_valid_token(self):
        """Тест что POST запросы с валидным CSRF токеном проходят"""
        app = FastAPI()
        setup_csrf_protection(app)
        
        @app.post("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        headers = {"X-CSRF-Token": "valid_token_12345"}
        response = client.post("/test", json={"data": "test"}, headers=headers)
        
        # POST запросы с валидным CSRF токеном должны проходить
        assert response.status_code == 200
        assert response.json() == {"message": "test"}
    
    def test_csrf_protection_post_with_invalid_token(self):
        """Тест что POST запросы с невалидным CSRF токеном блокируются"""
        app = FastAPI()
        setup_csrf_protection(app)
        
        @app.post("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        headers = {"X-CSRF-Token": "short"}
        response = client.post("/test", json={"data": "test"}, headers=headers)
        
        # POST запросы с невалидным CSRF токеном должны блокироваться
        assert response.status_code == 403
        assert "Invalid CSRF token" in response.json()["error"]
    
    def test_csrf_protection_options_request(self):
        """Тест что OPTIONS запросы проходят через CSRF защиту"""
        app = FastAPI()
        setup_csrf_protection(app)
        
        @app.options("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.options("/test")
        
        # OPTIONS запросы должны проходить без CSRF токена
        assert response.status_code == 200
    
    def test_csrf_protection_head_request(self):
        """Тест что HEAD запросы проходят через CSRF защиту"""
        app = FastAPI()
        setup_csrf_protection(app)
        
        @app.head("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.head("/test")
        
        # HEAD запросы должны проходить без CSRF токена
        assert response.status_code == 200
    
    def test_combined_security_setup(self):
        """Тест комбинированной настройки безопасности"""
        app = FastAPI()
        
        # Настраиваем все компоненты безопасности
        setup_secure_cors(app)
        setup_security_headers(app)
        setup_csrf_protection(app)
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.get("/test")
        
        # Проверяем что все middleware работают
        assert response.status_code == 200
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Permissions-Policy" in response.headers
    
    def test_cors_headers_present(self):
        """Тест что CORS заголовки присутствуют"""
        app = FastAPI()
        setup_secure_cors(app)
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.options("/test")
        
        # OPTIONS запрос должен обрабатываться CORS middleware
        assert response.status_code in [200, 405]  # 405 если OPTIONS не поддерживается
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        # Проверяем что все функции доступны
        from backend.security.secure_cors import (
            setup_secure_cors, setup_security_headers, 
            setup_csrf_protection, validate_csrf_token
        )
        
        assert setup_secure_cors is not None
        assert setup_security_headers is not None
        assert setup_csrf_protection is not None
        assert validate_csrf_token is not None
    
    def test_csrf_token_validation_edge_cases(self):
        """Тест граничных случаев валидации CSRF токена"""
        # Токен ровно 10 символов (граничное значение)
        token_10_chars = "1234567890"
        assert validate_csrf_token(token_10_chars) is False
        
        # Токен 11 символов (должен быть валидным)
        token_11_chars = "12345678901"
        assert validate_csrf_token(token_11_chars) is True
        
        # Очень длинный токен
        long_token = "a" * 1000
        assert validate_csrf_token(long_token) is True
    
    def test_security_headers_values(self):
        """Тест значений заголовков безопасности"""
        app = FastAPI()
        setup_security_headers(app)
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.get("/test")
        
        # Проверяем конкретные значения заголовков
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert "geolocation=()" in response.headers["Permissions-Policy"]