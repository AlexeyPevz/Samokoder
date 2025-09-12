#!/usr/bin/env python3
"""
Тесты для Auth API
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from fastapi import FastAPI
from backend.api.auth import (
    router, check_rate_limit, STRICT_RATE_LIMITS
)


class TestAuthAPI:
    """Тесты для Auth API модуля"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.app = FastAPI()
        self.app.include_router(router)
        self.client = TestClient(self.app)
    
    def test_check_rate_limit(self):
        """Тест проверки rate limiting"""
        # Функция всегда возвращает True (заглушка)
        assert check_rate_limit("192.168.1.1", "login") is True
        assert check_rate_limit("192.168.1.1", "register") is True
        assert check_rate_limit("unknown", "login") is True
    
    def test_strict_rate_limits_config(self):
        """Тест конфигурации строгих лимитов"""
        assert "login" in STRICT_RATE_LIMITS
        assert "register" in STRICT_RATE_LIMITS
        
        login_limits = STRICT_RATE_LIMITS["login"]
        assert login_limits["attempts"] == 3
        assert login_limits["window"] == 900  # 15 минут
        
        register_limits = STRICT_RATE_LIMITS["register"]
        assert register_limits["attempts"] == 5
        assert register_limits["window"] == 3600  # 1 час
    
    @patch('backend.api.auth.secure_password_validation')
    @patch('backend.api.auth.connection_pool_manager')
    @patch('backend.api.auth.execute_supabase_operation')
    def test_login_success(self, mock_execute_supabase, mock_connection_pool, mock_password_validation):
        """Тест успешного входа"""
        # Настраиваем моки
        mock_password_validation.return_value = True
        
        mock_supabase_client = Mock()
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        # Мокаем ответ Supabase auth
        mock_auth_response = Mock()
        mock_auth_response.user = Mock()
        mock_auth_response.user.id = "user123"
        mock_auth_response.session = Mock()
        mock_auth_response.session.access_token = "access_token_123"
        
        mock_supabase_client.auth.sign_in_with_password.return_value = mock_auth_response
        
        # Мокаем получение профиля
        mock_profile_response = Mock()
        mock_profile_response.data = [{
            "id": "user123",
            "email": "test@example.com",
            "full_name": "Test User",
            "avatar_url": None,
            "subscription_tier": "free",
            "subscription_status": "active",
            "api_credits_balance": 0.0,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
        mock_execute_supabase.return_value = mock_profile_response
        
        # Выполняем запрос
        response = self.client.post("/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Успешный вход"
        assert data["access_token"] == "access_token_123"
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 3600
        
        # Проверяем пользователя
        user = data["user"]
        assert user["id"] == "user123"
        assert user["email"] == "test@example.com"
        assert user["full_name"] == "Test User"
        assert user["subscription_tier"] == "free"
    
    @patch('backend.api.auth.secure_password_validation')
    def test_login_invalid_password(self, mock_password_validation):
        """Тест входа с невалидным паролем"""
        mock_password_validation.return_value = False
        
        response = self.client.post("/login", json={
            "email": "test@example.com",
            "password": "weak"
        })
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    @patch('backend.api.auth.secure_password_validation')
    @patch('backend.api.auth.connection_pool_manager')
    def test_login_supabase_auth_failed(self, mock_connection_pool, mock_password_validation):
        """Тест неудачной аутентификации в Supabase"""
        mock_password_validation.return_value = True
        
        mock_supabase_client = Mock()
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        # Мокаем неудачный ответ Supabase
        mock_auth_response = Mock()
        mock_auth_response.user = None
        mock_supabase_client.auth.sign_in_with_password.return_value = mock_auth_response
        
        response = self.client.post("/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!"
        })
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    @patch('backend.api.auth.secure_password_validation')
    @patch('backend.api.auth.connection_pool_manager')
    @patch('backend.api.auth.execute_supabase_operation')
    def test_login_profile_not_found(self, mock_execute_supabase, mock_connection_pool, mock_password_validation):
        """Тест входа когда профиль не найден"""
        mock_password_validation.return_value = True
        
        mock_supabase_client = Mock()
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        # Мокаем успешную аутентификацию
        mock_auth_response = Mock()
        mock_auth_response.user = Mock()
        mock_auth_response.user.id = "user123"
        mock_supabase_client.auth.sign_in_with_password.return_value = mock_auth_response
        
        # Мокаем пустой ответ профиля
        mock_profile_response = Mock()
        mock_profile_response.data = []
        mock_execute_supabase.return_value = mock_profile_response
        
        response = self.client.post("/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!"
        })
        
        assert response.status_code == 404
        assert "User profile not found" in response.json()["detail"]
    
    @patch('backend.api.auth.secure_password_validation')
    @patch('backend.api.auth.connection_pool_manager')
    @patch('backend.api.auth.execute_supabase_operation')
    def test_login_exception_handling(self, mock_execute_supabase, mock_connection_pool, mock_password_validation):
        """Тест обработки исключений при входе"""
        mock_password_validation.return_value = True
        
        # Мокаем исключение
        mock_connection_pool.get_supabase_client.side_effect = Exception("Connection error")
        
        response = self.client.post("/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!"
        })
        
        assert response.status_code == 500
        assert "Login failed" in response.json()["detail"]
    
    @patch('backend.api.auth.secure_password_validation')
    @patch('backend.api.auth.connection_pool_manager')
    @patch('backend.api.auth.execute_supabase_operation')
    def test_register_success(self, mock_execute_supabase, mock_connection_pool, mock_password_validation):
        """Тест успешной регистрации"""
        mock_password_validation.return_value = True
        
        mock_supabase_client = Mock()
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        # Мокаем успешную регистрацию в Supabase
        mock_auth_response = Mock()
        mock_auth_response.user = Mock()
        mock_auth_response.user.id = "user123"
        mock_supabase_client.auth.sign_up.return_value = mock_auth_response
        
        # Мокаем создание профиля
        mock_profile_response = Mock()
        mock_profile_response.data = [{"id": "user123"}]
        mock_execute_supabase.return_value = mock_profile_response
        
        response = self.client.post("/register", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "full_name": "Test User"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Пользователь успешно зарегистрирован"
        assert data["user_id"] == "user123"
        assert data["email"] == "test@example.com"
    
    @patch('backend.api.auth.secure_password_validation')
    def test_register_invalid_password(self, mock_password_validation):
        """Тест регистрации с невалидным паролем"""
        mock_password_validation.return_value = False
        
        response = self.client.post("/register", json={
            "email": "test@example.com",
            "password": "weak",
            "full_name": "Test User"
        })
        
        assert response.status_code == 400
        assert "Password does not meet security requirements" in response.json()["detail"]
    
    @patch('backend.api.auth.secure_password_validation')
    @patch('backend.api.auth.connection_pool_manager')
    def test_register_supabase_failed(self, mock_connection_pool, mock_password_validation):
        """Тест неудачной регистрации в Supabase"""
        mock_password_validation.return_value = True
        
        mock_supabase_client = Mock()
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        # Мокаем неудачную регистрацию
        mock_auth_response = Mock()
        mock_auth_response.user = None
        mock_supabase_client.auth.sign_up.return_value = mock_auth_response
        
        response = self.client.post("/register", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "full_name": "Test User"
        })
        
        assert response.status_code == 400
        assert "Registration failed" in response.json()["detail"]
    
    @patch('backend.api.auth.secure_password_validation')
    @patch('backend.api.auth.connection_pool_manager')
    @patch('backend.api.auth.execute_supabase_operation')
    def test_register_profile_creation_failed(self, mock_execute_supabase, mock_connection_pool, mock_password_validation):
        """Тест неудачного создания профиля"""
        mock_password_validation.return_value = True
        
        mock_supabase_client = Mock()
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        # Мокаем успешную регистрацию в Supabase
        mock_auth_response = Mock()
        mock_auth_response.user = Mock()
        mock_auth_response.user.id = "user123"
        mock_supabase_client.auth.sign_up.return_value = mock_auth_response
        
        # Мокаем неудачное создание профиля
        mock_profile_response = Mock()
        mock_profile_response.data = None
        mock_execute_supabase.return_value = mock_profile_response
        
        response = self.client.post("/register", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "full_name": "Test User"
        })
        
        assert response.status_code == 500
        assert "Failed to create user profile" in response.json()["detail"]
    
    @patch('backend.api.auth.connection_pool_manager')
    @patch('backend.api.auth.get_current_user')
    def test_logout_success(self, mock_get_current_user, mock_connection_pool):
        """Тест успешного выхода"""
        mock_get_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        
        mock_supabase_client = Mock()
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        response = self.client.post("/logout")
        
        assert response.status_code == 200
        assert "Успешный выход" in response.json()["message"]
        mock_supabase_client.auth.sign_out.assert_called_once()
    
    @patch('backend.api.auth.connection_pool_manager')
    @patch('backend.api.auth.get_current_user')
    def test_logout_exception(self, mock_get_current_user, mock_connection_pool):
        """Тест исключения при выходе"""
        mock_get_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        
        mock_supabase_client = Mock()
        mock_supabase_client.auth.sign_out.side_effect = Exception("Logout error")
        mock_connection_pool.get_supabase_client.return_value = mock_supabase_client
        
        response = self.client.post("/logout")
        
        assert response.status_code == 500
        assert "Logout failed" in response.json()["detail"]
    
    @patch('backend.api.auth.get_current_user')
    def test_get_current_user_info(self, mock_get_current_user):
        """Тест получения информации о текущем пользователе"""
        mock_user = {
            "id": "user123",
            "email": "test@example.com",
            "full_name": "Test User",
            "subscription_tier": "free"
        }
        mock_get_current_user.return_value = mock_user
        
        response = self.client.get("/me")
        
        assert response.status_code == 200
        assert response.json() == mock_user
    
    def test_router_exists(self):
        """Тест существования роутера"""
        assert router is not None
        assert hasattr(router, 'routes')
        assert len(router.routes) > 0
    
    def test_router_endpoints(self):
        """Тест наличия всех эндпоинтов"""
        endpoint_paths = [route.path for route in router.routes]
        
        assert "/login" in endpoint_paths
        assert "/register" in endpoint_paths
        assert "/logout" in endpoint_paths
        assert "/me" in endpoint_paths
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.api.auth import (
            router, check_rate_limit, STRICT_RATE_LIMITS
        )
        
        assert router is not None
        assert check_rate_limit is not None
        assert STRICT_RATE_LIMITS is not None
    
    def test_rate_limit_configuration(self):
        """Тест конфигурации rate limiting"""
        # Проверяем что лимиты настроены правильно
        assert STRICT_RATE_LIMITS["login"]["attempts"] <= 5  # Не слишком строго
        assert STRICT_RATE_LIMITS["login"]["window"] >= 300  # Минимум 5 минут
        
        assert STRICT_RATE_LIMITS["register"]["attempts"] <= 10  # Не слишком строго
        assert STRICT_RATE_LIMITS["register"]["window"] >= 600  # Минимум 10 минут
    
    @patch('backend.api.auth.check_rate_limit')
    def test_login_rate_limit_check(self, mock_check_rate_limit):
        """Тест проверки rate limiting при входе"""
        mock_check_rate_limit.return_value = False  # Блокируем
        
        response = self.client.post("/login", json={
            "email": "test@example.com",
            "password": "SecurePassword123!"
        })
        
        assert response.status_code == 429
        assert "Too many login attempts" in response.json()["detail"]
    
    @patch('backend.api.auth.check_rate_limit')
    def test_register_rate_limit_check(self, mock_check_rate_limit):
        """Тест проверки rate limiting при регистрации"""
        mock_check_rate_limit.return_value = False  # Блокируем
        
        response = self.client.post("/register", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "full_name": "Test User"
        })
        
        assert response.status_code == 429
        assert "Too many registration attempts" in response.json()["detail"]