"""
Контрактные тесты для API эндпоинтов
Проверяют соответствие реализации OpenAPI спецификации
"""

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from backend.main import app
from backend.models.requests import LoginRequest, RegisterRequest, ProjectCreateRequest
from backend.models.responses import (
    LoginResponse, RegisterResponse, ProjectResponse, 
    HealthCheckResponse, AIResponse, UserResponse
)

client = TestClient(app)

class TestAPIContracts:
    """Тесты контрактов API"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.mock_user = {
            "id": "test-user-123",
            "email": "test@example.com",
            "full_name": "Test User"
        }
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_health_endpoints_contract(self, mock_auth):
        """Тест контракта health эндпоинтов"""
        # GET /health
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "uptime" in data
        assert "services" in data
        
        # GET /health/detailed
        response = client.get("/health/detailed")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "external_services" in data
        assert "active_projects" in data
        assert "memory_usage" in data
        assert "disk_usage" in data
    
    def test_auth_login_contract(self):
        """Тест контракта аутентификации"""
        # POST /api/auth/login
        login_data = {
            "email": "test@example.com",
            "password": "SecurePassword123!"
        }
        
        with patch('backend.main.supabase_manager') as mock_supabase:
            mock_client = MagicMock()
            mock_user = MagicMock()
            mock_user.id = "test-user-123"
            mock_user.email = "test@example.com"
            mock_session = MagicMock()
            mock_session.access_token = "test-token"
            
            mock_client.auth.sign_in_with_password.return_value = MagicMock(
                user=mock_user,
                session=mock_session
            )
            mock_supabase.get_client.return_value = mock_client
            
            response = client.post("/api/auth/login", json=login_data)
            assert response.status_code == 200
            data = response.json()
            assert "message" in data
            assert "user" in data
            assert "session" in data
    
    def test_auth_register_contract(self):
        """Тест контракта регистрации"""
        # POST /api/auth/register
        register_data = {
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "full_name": "New User"
        }
        
        with patch('backend.main.supabase_manager') as mock_supabase:
            mock_client = MagicMock()
            mock_user = MagicMock()
            mock_user.id = "new-user-123"
            mock_user.email = "newuser@example.com"
            mock_user.created_at = "2025-01-01T00:00:00Z"
            mock_session = MagicMock()
            mock_session.access_token = "new-token"
            
            mock_client.auth.sign_up.return_value = MagicMock(
                user=mock_user,
                session=mock_session
            )
            mock_supabase.get_client.return_value = mock_client
            
            response = client.post("/api/auth/register", json=register_data)
            assert response.status_code == 200
            data = response.json()
            assert "message" in data
            assert "user" in data
            assert "access_token" in data
            assert "token_type" in data
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_projects_contract(self, mock_auth):
        """Тест контракта проектов"""
        mock_auth.return_value = self.mock_user
        
        # GET /api/projects
        with patch('backend.main.execute_supabase_operation') as mock_exec:
            mock_exec.return_value = MagicMock(data=[])
            response = client.get("/api/projects")
            assert response.status_code == 200
            data = response.json()
            assert "projects" in data
            assert "total_count" in data
        
        # POST /api/projects
        project_data = {
            "name": "Test Project",
            "description": "Test project description",
            "ai_config": {"model": "deepseek/deepseek-v3"}
        }
        
        with patch('backend.main.SamokoderGPTPilot') as mock_pilot:
            mock_instance = MagicMock()
            mock_instance.initialize_project.return_value = {
                "status": "success",
                "workspace": "test-workspace"
            }
            mock_pilot.return_value = mock_instance
            
            with patch('backend.main.execute_supabase_operation') as mock_exec:
                mock_exec.return_value = MagicMock(data=[{"id": "test-project"}])
                
                response = client.post("/api/projects", json=project_data)
                assert response.status_code == 200
                data = response.json()
                assert "project_id" in data
                assert "status" in data
                assert "message" in data
                assert "workspace" in data
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_ai_chat_contract(self, mock_auth):
        """Тест контракта AI чата"""
        mock_auth.return_value = self.mock_user
        
        chat_data = {
            "message": "Create a React component",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_ai_service') as mock_ai_service:
            mock_service = MagicMock()
            mock_response = MagicMock()
            mock_response.provider.value = "openrouter"
            mock_response.model = "deepseek/deepseek-v3"
            mock_response.tokens_used = 100
            mock_response.cost_usd = 0.01
            mock_response.response_time = 1.5
            mock_response.success = True
            mock_response.content = "Here's a React component..."
            mock_response.error = None
            
            mock_service.route_request.return_value = mock_response
            mock_ai_service.return_value = mock_service
            
            with patch('backend.main.execute_supabase_operation') as mock_exec:
                mock_exec.return_value = MagicMock(data=[])
                
                response = client.post("/api/ai/chat", json=chat_data)
                assert response.status_code == 200
                data = response.json()
                assert "content" in data
                assert "provider" in data
                assert "model" in data
                assert "tokens_used" in data
                assert "cost_usd" in data
                assert "response_time" in data
    
    def test_ai_providers_contract(self):
        """Тест контракта AI провайдеров"""
        response = client.get("/api/ai/providers")
        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
        assert isinstance(data["providers"], list)
        
        # Проверяем структуру провайдера
        provider = data["providers"][0]
        assert "id" in provider
        assert "name" in provider
        assert "description" in provider
        assert "website" in provider
        assert "requires_key" in provider
        assert "free_models" in provider
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_ai_usage_contract(self, mock_auth):
        """Тест контракта AI статистики"""
        mock_auth.return_value = self.mock_user
        
        with patch('backend.main.execute_supabase_operation') as mock_exec:
            mock_exec.return_value = MagicMock(data=[])
            
            with patch('backend.main.get_ai_service') as mock_ai_service:
                mock_service = MagicMock()
                mock_service.get_usage_stats.return_value = {
                    "total_requests": 10,
                    "total_tokens": 1000,
                    "total_cost": 0.05
                }
                mock_ai_service.return_value = mock_service
                
                response = client.get("/api/ai/usage")
                assert response.status_code == 200
                data = response.json()
                assert "total_requests" in data
                assert "total_tokens" in data
                assert "total_cost" in data
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_ai_validate_keys_contract(self, mock_auth):
        """Тест контракта валидации AI ключей"""
        mock_auth.return_value = self.mock_user
        
        keys_data = {
            "openrouter": "sk-or-test-key",
            "openai": "sk-test-key"
        }
        
        with patch('backend.main.get_ai_service') as mock_ai_service:
            mock_service = MagicMock()
            mock_service.validate_all_keys.return_value = {
                "openrouter": True,
                "openai": False
            }
            mock_ai_service.return_value = mock_service
            
            response = client.post("/api/ai/validate-keys", json=keys_data)
            assert response.status_code == 200
            data = response.json()
            assert "validation_results" in data
            assert "valid_keys" in data
            assert "invalid_keys" in data
            assert isinstance(data["valid_keys"], list)
            assert isinstance(data["invalid_keys"], list)
    
    def test_metrics_contract(self):
        """Тест контракта метрик"""
        response = client.get("/metrics")
        assert response.status_code == 200
        # Проверяем, что это Prometheus формат
        assert "text/plain" in response.headers.get("content-type", "")
    
    def test_root_contract(self):
        """Тест контракта корневого эндпоинта"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "status" in data
        assert "docs" in data


class TestMissingEndpoints:
    """Тесты для отсутствующих эндпоинтов"""
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_mfa_setup_contract(self, mock_auth):
        """Тест контракта MFA настройки"""
        mock_auth.return_value = {"id": "test-user-123", "email": "test@example.com"}
        
        response = client.post("/api/auth/mfa/setup")
        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "qr_code" in data
        assert "backup_codes" in data
        assert isinstance(data["backup_codes"], list)
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_mfa_verify_contract(self, mock_auth):
        """Тест контракта MFA проверки"""
        mock_auth.return_value = {"id": "test-user-123"}
        
        verify_data = {"code": "123456"}
        response = client.post("/api/auth/mfa/verify", json=verify_data)
        assert response.status_code == 200
        data = response.json()
        assert "verified" in data
        assert "message" in data
        assert isinstance(data["verified"], bool)
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_rbac_roles_contract(self, mock_auth):
        """Тест контракта RBAC ролей"""
        mock_auth.return_value = {"id": "test-user-123"}
        
        response = client.get("/api/rbac/roles")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if data:
            role = data[0]
            assert "id" in role
            assert "name" in role
            assert "description" in role
            assert "permissions" in role
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_api_keys_contract(self, mock_auth):
        """Тест контракта API ключей"""
        mock_auth.return_value = {"id": "test-user-123"}
        
        # GET /api/api-keys
        with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
            mock_exec.return_value = MagicMock(data=[])
            response = client.get("/api/api-keys/")
            assert response.status_code == 200
            data = response.json()
            assert "keys" in data
            assert "total_count" in data
            assert isinstance(data["keys"], list)


class TestErrorResponses:
    """Тесты контрактов error responses"""
    
    def test_validation_error_contract(self):
        """Тест контракта ошибок валидации"""
        # Неверные данные для логина
        response = client.post("/api/auth/login", json={"email": "invalid"})
        assert response.status_code == 422  # Validation error
        
        data = response.json()
        assert "detail" in data
    
    def test_authentication_error_contract(self):
        """Тест контракта ошибок аутентификации"""
        # Неверные учетные данные
        with patch('backend.main.supabase_manager') as mock_supabase:
            mock_client = MagicMock()
            mock_client.auth.sign_in_with_password.return_value = MagicMock(user=None)
            mock_supabase.get_client.return_value = mock_client
            
            response = client.post("/api/auth/login", json={
                "email": "test@example.com",
                "password": "wrongpassword"
            })
            assert response.status_code == 401
            data = response.json()
            assert "detail" in data
    
    def test_not_found_error_contract(self):
        """Тест контракта ошибок 404"""
        with patch('backend.auth.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = {"id": "test-user-123"}
            
            with patch('backend.main.execute_supabase_operation') as mock_exec:
                mock_exec.return_value = MagicMock(data=None)
                
                response = client.get("/api/projects/non-existent-project")
                assert response.status_code == 404
                data = response.json()
                assert "detail" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])