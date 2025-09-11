"""
Точные контрактные тесты для API эндпоинтов
Проверяют реальные структуры данных, а не идеализированные
"""

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from backend.main import app

client = TestClient(app)

class TestRealAPIContracts:
    """Тесты реальных контрактов API"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.mock_user = {
            "id": "test-user-123",
            "email": "test@example.com",
            "full_name": "Test User"
        }
    
    def test_real_login_contract(self):
        """Тест РЕАЛЬНОГО контракта login эндпоинта"""
        login_data = {
            "email": "test@example.com",
            "password": "SecurePassword123!"
        }
        
        with patch('backend.main.supabase_manager') as mock_supabase:
            # Mock режим - проверяем реальную структуру ответа
            mock_supabase.get_client.return_value = None
            
            response = client.post("/api/auth/login", json=login_data)
            assert response.status_code == 200
            data = response.json()
            
            # РЕАЛЬНАЯ структура ответа (не из спецификации!)
            assert "message" in data
            assert "user" in data
            assert "session" in data
            assert data["user"]["id"] == "mock_user_test@example.com"
            assert data["user"]["email"] == "test@example.com"
            assert data["session"]["access_token"] == "mock_token_test@example.com"
            assert data["session"]["token_type"] == "bearer"
            
            # НЕ должно быть полей из спецификации
            assert "success" not in data
            assert "access_token" not in data  # Это в session
            assert "expires_in" not in data
    
    def test_real_register_contract(self):
        """Тест РЕАЛЬНОГО контракта register эндпоинта"""
        register_data = {
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "full_name": "New User"
        }
        
        with patch('backend.main.supabase_manager') as mock_supabase:
            mock_supabase.get_client.return_value = None
            
            response = client.post("/api/auth/register", json=register_data)
            assert response.status_code == 200
            data = response.json()
            
            # РЕАЛЬНАЯ структура ответа
            assert "message" in data
            assert "user" in data
            assert "access_token" in data
            assert "token_type" in data
            
            # НЕ должно быть полей из спецификации
            assert "success" not in data
            assert "user_id" not in data  # Это в user.id
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_real_projects_contract(self, mock_auth):
        """Тест РЕАЛЬНОГО контракта projects эндпоинта"""
        mock_auth.return_value = self.mock_user
        
        with patch('backend.main.execute_supabase_operation') as mock_exec:
            mock_exec.return_value = MagicMock(data=[])
            
            response = client.get("/api/projects")
            assert response.status_code == 200
            data = response.json()
            
            # РЕАЛЬНАЯ структура ответа
            assert "projects" in data
            assert "total_count" in data
            
            # НЕ должно быть полей из спецификации
            assert "page" not in data
            assert "limit" not in data
            
            # Проверяем, что параметры запроса игнорируются
            response_with_params = client.get("/api/projects?limit=5&offset=10&status=draft&search=test")
            assert response_with_params.status_code == 200
            # Параметры должны игнорироваться - ответ одинаковый
            assert response_with_params.json() == data
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_real_ai_chat_contract(self, mock_auth):
        """Тест РЕАЛЬНОГО контракта AI chat эндпоинта"""
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
                
                # РЕАЛЬНАЯ структура ответа
                assert "content" in data
                assert "provider" in data
                assert "model" in data
                assert "tokens_used" in data
                assert "cost_usd" in data
                assert "response_time" in data
                
                # НЕ должно быть полей из спецификации
                assert "usage" not in data  # Это deprecated в спецификации
    
    def test_real_health_contract(self):
        """Тест РЕАЛЬНОГО контракта health эндпоинта"""
        with patch('backend.main.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.return_value = {
                "status": "healthy",
                "timestamp": "2024-12-19T15:30:00Z",
                "uptime": 86400.5,
                "uptime_seconds": 86400.5,
                "uptime_human": "1 day, 0:00:00",
                "services": {
                    "database": "healthy",
                    "redis": "healthy"
                }
            }
            
            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            
            # РЕАЛЬНАЯ структура ответа
            assert "status" in data
            assert "timestamp" in data
            assert "uptime" in data
            assert "services" in data
            
            # Дополнительные поля, которых нет в спецификации
            assert "uptime_seconds" in data
            assert "uptime_human" in data
    
    def test_missing_put_projects_endpoint(self):
        """Тест отсутствующего PUT /api/projects/{project_id} эндпоинта"""
        with patch('backend.auth.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = self.mock_user
            
            # Эндпоинт должен отсутствовать в main.py
            response = client.put("/api/projects/test-project-id", json={"name": "Updated"})
            assert response.status_code == 405  # Method Not Allowed
    
    def test_missing_ai_stream_endpoint(self):
        """Тест отсутствующего POST /api/ai/chat/stream эндпоинта"""
        with patch('backend.auth.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = self.mock_user
            
            # Эндпоинт должен отсутствовать в main.py
            response = client.post("/api/ai/chat/stream", json={"message": "test"})
            assert response.status_code == 405  # Method Not Allowed
    
    def test_auth_me_endpoint_missing(self):
        """Тест отсутствующего GET /api/auth/me эндпоинта"""
        with patch('backend.auth.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = self.mock_user
            
            # Эндпоинт должен отсутствовать
            response = client.get("/api/auth/me")
            assert response.status_code == 404  # Not Found
    
    def test_auth_user_endpoint_exists(self):
        """Тест существующего GET /api/auth/user эндпоинта"""
        with patch('backend.auth.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = self.mock_user
            
            response = client.get("/api/auth/user")
            assert response.status_code == 200
            data = response.json()
            
            # РЕАЛЬНАЯ структура ответа
            assert "user" in data
            assert "timestamp" in data
            assert data["user"] == self.mock_user


class TestRealErrorContracts:
    """Тесты реальных error contracts"""
    
    def test_real_validation_error(self):
        """Тест реальной структуры validation error"""
        # Неверные данные для логина
        response = client.post("/api/auth/login", json={"email": "invalid"})
        assert response.status_code == 422  # Validation error
        
        data = response.json()
        # FastAPI возвращает detail как массив
        assert "detail" in data
        assert isinstance(data["detail"], list)
    
    def test_real_authentication_error(self):
        """Тест реальной структуры authentication error"""
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
            
            # РЕАЛЬНАЯ структура error response
            assert "detail" in data
            assert data["detail"] == "Неверные учетные данные"


class TestRealParameterHandling:
    """Тесты реальной обработки параметров"""
    
    @patch('backend.auth.dependencies.get_current_user')
    def test_projects_ignores_query_params(self, mock_auth):
        """Тест что projects эндпоинт игнорирует query параметры"""
        mock_auth.return_value = self.mock_user
        
        with patch('backend.main.execute_supabase_operation') as mock_exec:
            mock_exec.return_value = MagicMock(data=[])
            
            # Запрос без параметров
            response1 = client.get("/api/projects")
            
            # Запрос с параметрами (должны игнорироваться)
            response2 = client.get("/api/projects?limit=5&offset=10&status=draft&search=test")
            
            # Ответы должны быть одинаковыми
            assert response1.json() == response2.json()
    
    def test_ai_chat_accepts_dict(self):
        """Тест что AI chat принимает dict вместо Pydantic модели"""
        with patch('backend.auth.dependencies.get_current_user') as mock_auth:
            mock_auth.return_value = {"id": "test-user"}
            
            with patch('backend.main.get_ai_service') as mock_ai_service:
                mock_service = MagicMock()
                mock_response = MagicMock()
                mock_response.success = True
                mock_response.content = "Test response"
                mock_response.provider.value = "openrouter"
                mock_response.model = "test-model"
                mock_response.tokens_used = 10
                mock_response.cost_usd = 0.001
                mock_response.response_time = 1.0
                mock_response.error = None
                
                mock_service.route_request.return_value = mock_response
                mock_ai_service.return_value = mock_service
                
                with patch('backend.main.execute_supabase_operation') as mock_exec:
                    mock_exec.return_value = MagicMock(data=[])
                    
                    # Передаем dict вместо Pydantic модели
                    response = client.post("/api/ai/chat", json={
                        "message": "test",
                        "invalid_field": "should_be_ignored"
                    })
                    
                    assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])