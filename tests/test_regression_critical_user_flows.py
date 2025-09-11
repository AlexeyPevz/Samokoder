"""
Регрессионные тесты для критических пользовательских потоков
Основано на анализе изменённых файлов в последних коммитах
"""

import pytest
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from backend.main import app
from backend.auth.dependencies import get_current_user
from backend.services.supabase_manager import supabase_manager
from backend.services.encryption_service import get_encryption_service

client = TestClient(app)

# Тестовые данные
TEST_USER = {
    "id": "test_user_123",
    "email": "test@example.com",
    "full_name": "Test User"
}

TEST_PROJECT = {
    "id": "test_project_123",
    "name": "Test Project",
    "description": "Test project description",
    "user_id": "test_user_123"
}

class TestAuthenticationFlow:
    """P0: Тесты критического потока аутентификации"""
    
    def test_user_registration_flow(self):
        """Тест: Полный поток регистрации пользователя"""
        # Шаг 1: Регистрация с валидными данными
        registration_data = {
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "full_name": "New User"
        }
        
        with patch('backend.api.auth.connection_pool_manager') as mock_pool:
            mock_supabase = MagicMock()
            mock_pool.get_supabase_client.return_value = mock_supabase
            
            # Мокаем успешную регистрацию
            mock_user = MagicMock()
            mock_user.id = "new_user_123"
            mock_user.email = "newuser@example.com"
            mock_user.created_at = datetime.now().isoformat()
            
            mock_response = MagicMock()
            mock_response.user = mock_user
            mock_response.session = MagicMock()
            mock_response.session.access_token = "mock_token_123"
            
            mock_supabase.auth.sign_up.return_value = mock_response
            mock_supabase.table.return_value.insert.return_value.execute.return_value = MagicMock()
            
            response = client.post("/api/auth/register", json=registration_data)
            
            # Проверяем успешную регистрацию
            assert response.status_code == 200
            data = response.json()
            assert "user_id" in data
            assert data["email"] == "newuser@example.com"
            assert "message" in data
    
    def test_user_login_flow(self):
        """Тест: Полный поток входа пользователя"""
        # Шаг 1: Вход с валидными данными
        login_data = {
            "email": "test@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('backend.main.supabase_manager') as mock_manager:
            mock_client = MagicMock()
            mock_manager.get_client.return_value = mock_client
            
            # Мокаем успешный вход
            mock_user = MagicMock()
            mock_user.id = "test_user_123"
            mock_user.email = "test@example.com"
            mock_user.created_at = datetime.now().isoformat()
            
            mock_response = MagicMock()
            mock_response.user = mock_user
            mock_response.session = MagicMock()
            mock_response.session.access_token = "mock_token_123"
            
            mock_client.auth.sign_in_with_password.return_value = mock_response
            
            response = client.post("/api/auth/login", json=login_data)
            
            # Проверяем успешный вход
            assert response.status_code == 200
            data = response.json()
            assert "user" in data
            assert "session" in data
            assert data["user"]["email"] == "test@example.com"
    
    def test_password_validation_security(self):
        """Тест: Валидация безопасности паролей"""
        weak_passwords = [
            "123",  # Слишком короткий
            "password",  # Нет цифр и спецсимволов
            "12345678",  # Только цифры
            "Password",  # Нет цифр и спецсимволов
        ]
        
        for weak_password in weak_passwords:
            registration_data = {
                "email": "test@example.com",
                "password": weak_password,
                "full_name": "Test User"
            }
            
            response = client.post("/api/auth/register", json=registration_data)
            # Должен быть отклонён из-за слабого пароля
            assert response.status_code in [400, 422]
    
    def test_rate_limiting_auth(self):
        """Тест: Rate limiting для аутентификации"""
        login_data = {
            "email": "test@example.com",
            "password": "SecurePass123!"
        }
        
        # Делаем множественные попытки входа
        for i in range(10):
            response = client.post("/api/auth/login", json=login_data)
            if i >= 3:  # После 3 попыток должен сработать rate limiting
                assert response.status_code == 429
                break
    
    def test_jwt_token_validation(self):
        """Тест: Валидация JWT токенов"""
        # Тест с невалидным токеном
        response = client.get(
            "/api/auth/user",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
        
        # Тест с истекшим токеном
        expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MDAwMDAwMDB9.invalid"
        response = client.get(
            "/api/auth/user",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401

class TestProjectManagementFlow:
    """P0: Тесты критического потока управления проектами"""
    
    def test_project_creation_flow(self):
        """Тест: Полный поток создания проекта"""
        project_data = {
            "name": "Test Project",
            "description": "Test project description",
            "ai_config": {"model": "deepseek/deepseek-v3"},
            "tech_stack": {"frontend": "React", "backend": "FastAPI"}
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager, \
             patch('backend.main.SamokoderGPTPilot') as mock_pilot:
            
            # Мокаем аутентификацию
            mock_auth.return_value = TEST_USER
            
            # Мокаем Supabase
            mock_client = MagicMock()
            mock_manager.get_client.return_value = mock_client
            mock_manager.execute_supabase_operation = AsyncMock()
            
            # Мокаем GPT Pilot
            mock_pilot_instance = MagicMock()
            mock_pilot_instance.initialize_project = AsyncMock(return_value={
                "status": "success",
                "workspace": "workspaces/test_user_123/test_project_123"
            })
            mock_pilot.return_value = mock_pilot_instance
            
            response = client.post("/api/projects", json=project_data)
            
            # Проверяем успешное создание проекта
            assert response.status_code == 200
            data = response.json()
            assert "project_id" in data
            assert data["status"] == "draft"
            assert "message" in data
    
    def test_project_listing_flow(self):
        """Тест: Получение списка проектов пользователя"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            # Мокаем аутентификацию
            mock_auth.return_value = TEST_USER
            
            # Мокаем Supabase ответ
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[TEST_PROJECT]
            ))
            
            response = client.get("/api/projects")
            
            # Проверяем успешное получение списка
            assert response.status_code == 200
            data = response.json()
            assert "projects" in data
            assert "total_count" in data
            assert len(data["projects"]) >= 0
    
    def test_project_access_control(self):
        """Тест: Контроль доступа к проектам"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            # Мокаем аутентификацию другого пользователя
            other_user = {"id": "other_user_123", "email": "other@example.com"}
            mock_auth.return_value = other_user
            
            # Мокаем пустой ответ (проект не найден)
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=None
            ))
            
            response = client.get(f"/api/projects/{TEST_PROJECT['id']}")
            
            # Должен быть отклонён из-за отсутствия доступа
            assert response.status_code == 404
    
    def test_project_deletion_flow(self):
        """Тест: Удаление проекта"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            # Мокаем аутентификацию
            mock_auth.return_value = TEST_USER
            
            # Мокаем успешное удаление
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[TEST_PROJECT]
            ))
            
            response = client.delete(f"/api/projects/{TEST_PROJECT['id']}")
            
            # Проверяем успешное удаление
            assert response.status_code == 200
            data = response.json()
            assert "message" in data

class TestAIServiceFlow:
    """P1: Тесты потока AI сервиса"""
    
    def test_ai_chat_flow(self):
        """Тест: Полный поток чата с AI"""
        chat_data = {
            "message": "Создай простое React приложение",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            # Мокаем аутентификацию
            mock_auth.return_value = TEST_USER
            
            # Мокаем AI сервис
            mock_ai_instance = MagicMock()
            mock_ai_instance.route_request = AsyncMock(return_value=MagicMock(
                content="Вот простое React приложение...",
                provider="openrouter",
                model="deepseek/deepseek-v3",
                tokens_used=150,
                cost_usd=0.001,
                success=True
            ))
            mock_ai_service.return_value = mock_ai_instance
            
            # Мокаем Supabase
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.post("/api/ai/chat", json=chat_data)
            
            # Проверяем успешный ответ AI
            assert response.status_code == 200
            data = response.json()
            assert "content" in data
            assert "provider" in data
            assert "model" in data
    
    def test_ai_usage_tracking(self):
        """Тест: Отслеживание использования AI"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            # Мокаем аутентификацию
            mock_auth.return_value = TEST_USER
            
            # Мокаем данные использования
            usage_data = [
                {
                    "provider": "openrouter",
                    "tokens_used": 1000,
                    "cost": 0.01,
                    "created_at": datetime.now().isoformat()
                }
            ]
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=usage_data
            ))
            
            response = client.get("/api/ai/usage")
            
            # Проверяем получение статистики
            assert response.status_code == 200
            data = response.json()
            assert "total_tokens" in data
            assert "total_cost" in data

class TestSecurityMiddlewareFlow:
    """P0: Тесты безопасности и middleware"""
    
    def test_cors_preflight_requests(self):
        """Тест: CORS preflight запросы"""
        response = client.options("/api/projects")
        
        # Проверяем CORS заголовки
        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
    
    def test_csrf_protection(self):
        """Тест: CSRF защита"""
        # POST запрос без CSRF токена должен быть отклонён
        response = client.post(
            "/api/projects",
            json={"name": "Test", "description": "Test"},
            headers={"X-CSRF-Token": ""}
        )
        assert response.status_code == 403
        
        # POST запрос с валидным CSRF токеном должен пройти
        response = client.post(
            "/api/projects",
            json={"name": "Test", "description": "Test"},
            headers={"X-CSRF-Token": "valid_csrf_token_123"}
        )
        # Может быть 401 из-за отсутствия аутентификации, но не 403 CSRF
        assert response.status_code != 403
    
    def test_security_headers(self):
        """Тест: Безопасные HTTP заголовки"""
        response = client.get("/")
        
        # Проверяем наличие безопасных заголовков
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert "Strict-Transport-Security" in response.headers
    
    def test_input_validation(self):
        """Тест: Валидация входных данных"""
        # Тест с невалидными данными проекта
        invalid_project_data = {
            "name": "",  # Пустое имя
            "description": None  # None вместо строки
        }
        
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.return_value = TEST_USER
            
            response = client.post("/api/projects", json=invalid_project_data)
            assert response.status_code == 400

class TestIntegrationFlows:
    """P0: Интеграционные тесты полных пользовательских потоков"""
    
    def test_complete_user_journey(self):
        """Тест: Полный путь пользователя от регистрации до создания проекта"""
        # Шаг 1: Регистрация
        registration_data = {
            "email": "journey@example.com",
            "password": "SecurePass123!",
            "full_name": "Journey User"
        }
        
        with patch('backend.api.auth.connection_pool_manager') as mock_pool:
            mock_supabase = MagicMock()
            mock_pool.get_supabase_client.return_value = mock_supabase
            
            mock_user = MagicMock()
            mock_user.id = "journey_user_123"
            mock_user.email = "journey@example.com"
            
            mock_response = MagicMock()
            mock_response.user = mock_user
            mock_response.session = MagicMock()
            mock_response.session.access_token = "journey_token_123"
            
            mock_supabase.auth.sign_up.return_value = mock_response
            mock_supabase.table.return_value.insert.return_value.execute.return_value = MagicMock()
            
            # Регистрация
            response = client.post("/api/auth/register", json=registration_data)
            assert response.status_code == 200
            
            # Шаг 2: Вход
            login_data = {
                "email": "journey@example.com",
                "password": "SecurePass123!"
            }
            
            mock_supabase.auth.sign_in_with_password.return_value = mock_response
            
            response = client.post("/api/auth/login", json=login_data)
            assert response.status_code == 200
            
            # Шаг 3: Создание проекта
            project_data = {
                "name": "Journey Project",
                "description": "Project created during user journey"
            }
            
            with patch('backend.main.get_current_user') as mock_auth, \
                 patch('backend.main.supabase_manager') as mock_manager, \
                 patch('backend.main.SamokoderGPTPilot') as mock_pilot:
                
                mock_auth.return_value = {"id": "journey_user_123", "email": "journey@example.com"}
                
                mock_client = MagicMock()
                mock_manager.get_client.return_value = mock_client
                mock_manager.execute_supabase_operation = AsyncMock()
                
                mock_pilot_instance = MagicMock()
                mock_pilot_instance.initialize_project = AsyncMock(return_value={
                    "status": "success",
                    "workspace": "workspaces/journey_user_123/journey_project_123"
                })
                mock_pilot.return_value = mock_pilot_instance
                
                response = client.post("/api/projects", json=project_data)
                assert response.status_code == 200
                
                # Шаг 4: Получение списка проектов
                mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                    data=[{
                        "id": "journey_project_123",
                        "name": "Journey Project",
                        "description": "Project created during user journey",
                        "user_id": "journey_user_123"
                    }]
                ))
                
                response = client.get("/api/projects")
                assert response.status_code == 200
                data = response.json()
                assert len(data["projects"]) >= 1

class TestPerformanceBoundaries:
    """P1: Тесты производительности критических эндпоинтов"""
    
    def test_auth_endpoint_performance(self):
        """Тест: Производительность эндпоинтов аутентификации"""
        import time
        
        login_data = {
            "email": "perf@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('backend.main.supabase_manager') as mock_manager:
            mock_client = MagicMock()
            mock_manager.get_client.return_value = mock_client
            
            mock_user = MagicMock()
            mock_user.id = "perf_user_123"
            mock_user.email = "perf@example.com"
            
            mock_response = MagicMock()
            mock_response.user = mock_user
            mock_response.session = MagicMock()
            mock_response.session.access_token = "perf_token_123"
            
            mock_client.auth.sign_in_with_password.return_value = mock_response
            
            # Измеряем время ответа
            start_time = time.time()
            response = client.post("/api/auth/login", json=login_data)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Проверяем, что ответ получен быстро (менее 2 секунд)
            assert response_time < 2.0
            assert response.status_code == 200
    
    def test_project_creation_performance(self):
        """Тест: Производительность создания проекта"""
        import time
        
        project_data = {
            "name": "Performance Test Project",
            "description": "Testing project creation performance"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager, \
             patch('backend.main.SamokoderGPTPilot') as mock_pilot:
            
            mock_auth.return_value = TEST_USER
            
            mock_client = MagicMock()
            mock_manager.get_client.return_value = mock_client
            mock_manager.execute_supabase_operation = AsyncMock()
            
            mock_pilot_instance = MagicMock()
            mock_pilot_instance.initialize_project = AsyncMock(return_value={
                "status": "success",
                "workspace": "workspaces/test_user_123/perf_project_123"
            })
            mock_pilot.return_value = mock_pilot_instance
            
            # Измеряем время ответа
            start_time = time.time()
            response = client.post("/api/projects", json=project_data)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Проверяем, что ответ получен быстро (менее 5 секунд)
            assert response_time < 5.0
            assert response.status_code == 200

# Вспомогательные функции для тестирования
def create_test_user():
    """Создаёт тестового пользователя"""
    return {
        "id": str(uuid.uuid4()),
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "full_name": "Test User"
    }

def create_test_project(user_id):
    """Создаёт тестовый проект"""
    return {
        "id": str(uuid.uuid4()),
        "name": f"Test Project {uuid.uuid4().hex[:8]}",
        "description": "Test project description",
        "user_id": user_id
    }

# Фикстуры для pytest
@pytest.fixture
def test_user():
    return create_test_user()

@pytest.fixture
def test_project(test_user):
    return create_test_project(test_user["id"])

@pytest.fixture
def auth_headers(test_user):
    return {"Authorization": f"Bearer mock_token_{test_user['id']}"}

if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, "-v", "--tb=short"])