"""Tests for rate limiting middleware."""
import pytest
from fastapi.testclient import TestClient
from samokoder.api.main import app


client = TestClient(app)


class TestRateLimiting:
    """Tests for rate limiting on various endpoints."""
    
    def test_auth_login_rate_limit(self):
        """Тест rate limiting на /auth/login (5 requests/minute)."""
        # Первые 5 запросов должны пройти
        for i in range(5):
            response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": f"test{i}@example.com",
                    "password": "wrongpassword"
                }
            )
            # Может быть 401 (wrong credentials) или 422 (validation error)
            # Но НЕ 429 (rate limit)
            assert response.status_code != 429, f"Request {i+1} should not be rate limited"
        
        # 6-й запрос должен быть rate limited
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "password"
            }
        )
        assert response.status_code == 429, "6th request should be rate limited"
        assert "Retry-After" in response.headers or "X-RateLimit-Limit" in response.headers
    
    def test_auth_register_rate_limit(self):
        """Тест rate limiting на /auth/register (5 requests/minute)."""
        # Первые 5 запросов
        for i in range(5):
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "email": f"test{i}@example.com",
                    "username": f"testuser{i}",
                    "password": "Password123!",
                    "confirm_password": "Password123!"
                }
            )
            # Может быть 201 (created) или 400 (validation/duplicate)
            assert response.status_code != 429, f"Request {i+1} should not be rate limited"
        
        # 6-й запрос должен быть rate limited
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "test6@example.com",
                "username": "testuser6",
                "password": "Password123!",
                "confirm_password": "Password123!"
            }
        )
        assert response.status_code == 429, "6th request should be rate limited"
    
    def test_rate_limit_headers(self):
        """Тест наличия rate limit headers в ответе."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "password"
            }
        )
        
        # Проверяем наличие X-RateLimit-* headers
        assert "X-RateLimit-Limit" in response.headers or "RateLimit-Limit" in response.headers
        # При первом запросе should have remaining > 0
        # (это зависит от предыдущих тестов, но проверяем наличие header)
    
    @pytest.mark.skip(reason="Requires authenticated user token")
    def test_projects_list_rate_limit(self):
        """Тест rate limiting на /projects (100 requests/minute для authenticated)."""
        # Этот тест требует JWT токен
        # Пропускаем в unit тестах, должен быть в integration тестах
        pass
    
    @pytest.mark.skip(reason="Requires authenticated user token")
    def test_project_create_rate_limit(self):
        """Тест rate limiting на POST /projects (10/day)."""
        # Этот тест требует JWT токен
        # Пропускаем в unit тестах, должен быть в integration тестах
        pass


class TestRateLimitConfiguration:
    """Tests for rate limit configuration."""
    
    def test_rate_limits_defined(self):
        """Тест что все лимиты определены."""
        from api.middleware.rate_limiter import LIMITS
        
        assert "public" in LIMITS
        assert "authenticated" in LIMITS
        assert "project_create" in LIMITS
        assert "auth" in LIMITS
        assert "llm_generate" in LIMITS
    
    def test_get_rate_limit(self):
        """Тест функции get_rate_limit."""
        from api.middleware.rate_limiter import get_rate_limit
        
        assert get_rate_limit("auth") == "5/minute"
        assert get_rate_limit("public") == "10/minute"
        assert get_rate_limit("authenticated") == "100/minute"
        assert get_rate_limit("project_create") == "10/day"
        assert get_rate_limit("llm_generate") == "50/hour"
        
        # Несуществующий тип должен вернуть дефолтный
        assert get_rate_limit("nonexistent") == "100/minute"
