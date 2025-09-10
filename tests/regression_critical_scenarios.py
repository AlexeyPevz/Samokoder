"""
Регрессионные тесты критических пользовательских сценариев
QA/Тест-инженер с 20-летним опытом
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
from unittest.mock import Mock, patch, AsyncMock
import httpx
from fastapi.testclient import TestClient

# Импорты приложения
from backend.main_refactored import create_app
from backend.models.database import Profile, Project, UserSettings
from backend.services.ai_service import AIService
from backend.auth.dependencies import get_current_user

class CriticalScenarioTester:
    """Тестер критических пользовательских сценариев"""
    
    def __init__(self):
        self.app = create_app()
        self.client = TestClient(self.app)
        self.test_user_id = "test-user-123"
        self.test_project_id = "test-project-456"
        
    def setup_test_data(self):
        """Настройка тестовых данных"""
        self.test_user = {
            "id": self.test_user_id,
            "email": "test@example.com",
            "full_name": "Test User",
            "subscription_tier": "professional",
            "subscription_status": "active"
        }
        
        self.test_project = {
            "id": self.test_project_id,
            "user_id": self.test_user_id,
            "name": "Test Project",
            "description": "Test project description",
            "status": "draft",
            "tech_stack": {"frontend": "react", "backend": "python"}
        }

class TestCriticalUserScenarios:
    """Тесты критических пользовательских сценариев"""
    
    @pytest.fixture
    def tester(self):
        """Создать тестер"""
        return CriticalScenarioTester()
    
    @pytest.fixture
    def auth_headers(self, tester):
        """Заголовки аутентификации"""
        return {"Authorization": f"Bearer {tester.test_user_id}"}
    
    # ==================== СЦЕНАРИЙ 1: ПОЛНЫЙ ЖИЗНЕННЫЙ ЦИКЛ ПРОЕКТА ====================
    
    def test_scenario_1_complete_project_lifecycle(self, tester, auth_headers):
        """P0: Полный жизненный цикл проекта - от создания до завершения"""
        
        # 1. Создание проекта
        project_data = {
            "name": "E-commerce Platform",
            "description": "Full-stack e-commerce solution",
            "tech_stack": {
                "frontend": "react",
                "backend": "python",
                "database": "postgresql"
            }
        }
        
        response = tester.client.post(
            "/api/projects/",
            json=project_data,
            headers=auth_headers
        )
        
        assert response.status_code == 201
        project_id = response.json()["id"]
        
        # 2. Настройка AI конфигурации
        ai_config = {
            "provider": "openrouter",
            "model": "deepseek/deepseek-v3",
            "api_key": "test-api-key"
        }
        
        response = tester.client.put(
            f"/api/projects/{project_id}/ai-config",
            json=ai_config,
            headers=auth_headers
        )
        assert response.status_code == 200
        
        # 3. Запуск генерации кода
        generation_request = {
            "prompt": "Create a modern e-commerce platform with user authentication, product catalog, and shopping cart",
            "features": ["auth", "catalog", "cart", "checkout"]
        }
        
        response = tester.client.post(
            f"/api/projects/{project_id}/generate",
            json=generation_request,
            headers=auth_headers
        )
        assert response.status_code == 202
        
        # 4. Мониторинг прогресса
        for _ in range(5):  # Проверяем прогресс 5 раз
            response = tester.client.get(
                f"/api/projects/{project_id}/status",
                headers=auth_headers
            )
            assert response.status_code == 200
            status = response.json()
            
            if status["status"] == "completed":
                break
            elif status["status"] == "error":
                pytest.fail("Project generation failed")
            
            # Имитируем ожидание
            import time
            time.sleep(0.1)
        
        # 5. Получение сгенерированного кода
        response = tester.client.get(
            f"/api/projects/{project_id}/files",
            headers=auth_headers
        )
        assert response.status_code == 200
        files = response.json()
        assert len(files) > 0
        
        # 6. Экспорт проекта
        response = tester.client.get(
            f"/api/projects/{project_id}/export",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        
        # 7. Архивирование проекта
        response = tester.client.delete(
            f"/api/projects/{project_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
    
    # ==================== СЦЕНАРИЙ 2: АУТЕНТИФИКАЦИЯ И УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЕМ ====================
    
    def test_scenario_2_user_authentication_flow(self, tester):
        """P0: Полный цикл аутентификации пользователя"""
        
        # 1. Регистрация нового пользователя
        registration_data = {
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "full_name": "New User"
        }
        
        response = tester.client.post("/api/auth/register", json=registration_data)
        assert response.status_code == 201
        user_data = response.json()
        assert "access_token" in user_data
        
        # 2. Вход в систему
        login_data = {
            "email": "newuser@example.com",
            "password": "SecurePassword123!"
        }
        
        response = tester.client.post("/api/auth/login", json=login_data)
        assert response.status_code == 200
        login_response = response.json()
        assert "access_token" in login_response
        
        # 3. Получение профиля
        headers = {"Authorization": f"Bearer {login_response['access_token']}"}
        response = tester.client.get("/api/auth/profile", headers=headers)
        assert response.status_code == 200
        profile = response.json()
        assert profile["email"] == "newuser@example.com"
        
        # 4. Обновление профиля
        update_data = {
            "full_name": "Updated User Name",
            "subscription_tier": "professional"
        }
        
        response = tester.client.put("/api/auth/profile", json=update_data, headers=headers)
        assert response.status_code == 200
        
        # 5. Смена пароля
        password_change_data = {
            "current_password": "SecurePassword123!",
            "new_password": "NewSecurePassword456!"
        }
        
        response = tester.client.put("/api/auth/change-password", json=password_change_data, headers=headers)
        assert response.status_code == 200
        
        # 6. Выход из системы
        response = tester.client.post("/api/auth/logout", headers=headers)
        assert response.status_code == 200
    
    # ==================== СЦЕНАРИЙ 3: AI ИНТЕГРАЦИЯ И FALLBACK ====================
    
    def test_scenario_3_ai_integration_fallback(self, tester, auth_headers):
        """P0: AI интеграция с fallback механизмом"""
        
        # 1. Создание проекта
        project_data = {
            "name": "AI Test Project",
            "description": "Testing AI integration",
            "tech_stack": {"frontend": "react"}
        }
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 201
        project_id = response.json()["id"]
        
        # 2. Тест с основным провайдером (успешный)
        with patch('backend.services.ai_service.AIService.generate_code') as mock_generate:
            mock_generate.return_value = {
                "status": "success",
                "files": [{"name": "App.js", "content": "console.log('Hello World');"}]
            }
            
            generation_request = {
                "prompt": "Create a simple React app",
                "provider": "openrouter",
                "model": "deepseek/deepseek-v3"
            }
            
            response = tester.client.post(
                f"/api/projects/{project_id}/generate",
                json=generation_request,
                headers=auth_headers
            )
            assert response.status_code == 202
        
        # 3. Тест с fallback провайдером (основной недоступен)
        with patch('backend.services.ai_service.AIService.generate_code') as mock_generate:
            # Первый провайдер недоступен
            mock_generate.side_effect = [
                Exception("Primary provider unavailable"),
                {"status": "success", "files": [{"name": "App.js", "content": "console.log('Fallback');"}]}
            ]
            
            response = tester.client.post(
                f"/api/projects/{project_id}/generate",
                json=generation_request,
                headers=auth_headers
            )
            assert response.status_code == 202
        
        # 4. Тест с полным отказом всех провайдеров
        with patch('backend.services.ai_service.AIService.generate_code') as mock_generate:
            mock_generate.side_effect = Exception("All providers unavailable")
            
            response = tester.client.post(
                f"/api/projects/{project_id}/generate",
                json=generation_request,
                headers=auth_headers
            )
            assert response.status_code == 503
    
    # ==================== СЦЕНАРИЙ 4: УПРАВЛЕНИЕ ПОДПИСКАМИ И ЛИМИТАМИ ====================
    
    def test_scenario_4_subscription_limits_management(self, tester, auth_headers):
        """P0: Управление подписками и лимитами"""
        
        # 1. Проверка текущих лимитов
        response = tester.client.get("/api/auth/limits", headers=auth_headers)
        assert response.status_code == 200
        limits = response.json()
        assert "max_projects" in limits
        assert "current_projects" in limits
        
        # 2. Создание проектов до достижения лимита
        max_projects = limits["max_projects"]
        created_projects = []
        
        for i in range(max_projects):
            project_data = {
                "name": f"Test Project {i+1}",
                "description": f"Test project {i+1}",
                "tech_stack": {"frontend": "react"}
            }
            
            response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
            assert response.status_code == 201
            created_projects.append(response.json()["id"])
        
        # 3. Попытка превысить лимит
        project_data = {
            "name": "Excess Project",
            "description": "This should fail",
            "tech_stack": {"frontend": "react"}
        }
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 403
        assert "limit exceeded" in response.json()["detail"].lower()
        
        # 4. Обновление подписки
        subscription_data = {
            "subscription_tier": "business",
            "subscription_status": "active"
        }
        
        response = tester.client.put("/api/auth/subscription", json=subscription_data, headers=auth_headers)
        assert response.status_code == 200
        
        # 5. Проверка новых лимитов
        response = tester.client.get("/api/auth/limits", headers=auth_headers)
        assert response.status_code == 200
        new_limits = response.json()
        assert new_limits["max_projects"] > max_projects
    
    # ==================== СЦЕНАРИЙ 5: ОБРАБОТКА ОШИБОК И ВОССТАНОВЛЕНИЕ ====================
    
    def test_scenario_5_error_handling_recovery(self, tester, auth_headers):
        """P0: Обработка ошибок и восстановление"""
        
        # 1. Создание проекта
        project_data = {
            "name": "Error Test Project",
            "description": "Testing error handling",
            "tech_stack": {"frontend": "react"}
        }
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 201
        project_id = response.json()["id"]
        
        # 2. Тест с некорректными данными
        invalid_data = {
            "prompt": "",  # Пустой промпт
            "features": []  # Пустой список функций
        }
        
        response = tester.client.post(
            f"/api/projects/{project_id}/generate",
            json=invalid_data,
            headers=auth_headers
        )
        assert response.status_code == 400
        
        # 3. Тест с несуществующим проектом
        response = tester.client.get("/api/projects/non-existent-id", headers=auth_headers)
        assert response.status_code == 404
        
        # 4. Тест с неавторизованным доступом
        response = tester.client.get(f"/api/projects/{project_id}")
        assert response.status_code == 401
        
        # 5. Тест восстановления после ошибки
        valid_data = {
            "prompt": "Create a simple app",
            "features": ["basic"]
        }
        
        response = tester.client.post(
            f"/api/projects/{project_id}/generate",
            json=valid_data,
            headers=auth_headers
        )
        assert response.status_code == 202

class TestNegativeAndBoundaryCases:
    """Негативные и граничные тест-кейсы"""
    
    @pytest.fixture
    def tester(self):
        return CriticalScenarioTester()
    
    @pytest.fixture
    def auth_headers(self, tester):
        return {"Authorization": f"Bearer {tester.test_user_id}"}
    
    # ==================== НЕГАТИВНЫЕ ТЕСТЫ ====================
    
    def test_negative_invalid_email_format(self, tester):
        """Негативный тест: некорректный формат email"""
        invalid_emails = [
            "invalid-email",
            "@domain.com",
            "user@",
            "user@domain",
            "user..name@domain.com",
            "user@domain..com"
        ]
        
        for email in invalid_emails:
            registration_data = {
                "email": email,
                "password": "ValidPassword123!",
                "full_name": "Test User"
            }
            
            response = tester.client.post("/api/auth/register", json=registration_data)
            assert response.status_code == 400
    
    def test_negative_weak_passwords(self, tester):
        """Негативный тест: слабые пароли"""
        weak_passwords = [
            "123456",
            "password",
            "qwerty",
            "abc123",
            "Password",  # Без цифр и спецсимволов
            "password123",  # Без заглавных букв
            "PASSWORD123",  # Без строчных букв
            "Pass123"  # Слишком короткий
        ]
        
        for password in weak_passwords:
            registration_data = {
                "email": f"test{password}@example.com",
                "password": password,
                "full_name": "Test User"
            }
            
            response = tester.client.post("/api/auth/register", json=registration_data)
            assert response.status_code == 400
    
    def test_negative_sql_injection_attempts(self, tester, auth_headers):
        """Негативный тест: попытки SQL injection"""
        sql_injections = [
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users--",
            "admin' OR '1'='1",
            "'; EXEC xp_cmdshell('dir'); --"
        ]
        
        for injection in sql_injections:
            # Попытка в имени проекта
            project_data = {
                "name": injection,
                "description": "Test project",
                "tech_stack": {"frontend": "react"}
            }
            
            response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
            assert response.status_code == 400
    
    def test_negative_xss_attempts(self, tester, auth_headers):
        """Негативный тест: попытки XSS атак"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert('xss')",
            "<iframe src='evil.com'></iframe>"
        ]
        
        for payload in xss_payloads:
            project_data = {
                "name": payload,
                "description": "Test project",
                "tech_stack": {"frontend": "react"}
            }
            
            response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
            assert response.status_code == 400
    
    # ==================== ГРАНИЧНЫЕ ТЕСТЫ ====================
    
    def test_boundary_max_project_name_length(self, tester, auth_headers):
        """Граничный тест: максимальная длина имени проекта"""
        # Максимальная допустимая длина
        max_name = "A" * 255
        project_data = {
            "name": max_name,
            "description": "Test project",
            "tech_stack": {"frontend": "react"}
        }
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 201
        
        # Превышение максимальной длины
        too_long_name = "A" * 256
        project_data["name"] = too_long_name
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 400
    
    def test_boundary_max_description_length(self, tester, auth_headers):
        """Граничный тест: максимальная длина описания"""
        # Максимальная допустимая длина
        max_description = "A" * 1000
        project_data = {
            "name": "Test Project",
            "description": max_description,
            "tech_stack": {"frontend": "react"}
        }
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 201
        
        # Превышение максимальной длины
        too_long_description = "A" * 1001
        project_data["description"] = too_long_description
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 400
    
    def test_boundary_rate_limiting(self, tester, auth_headers):
        """Граничный тест: rate limiting"""
        # Создаем много запросов подряд
        for i in range(100):  # Лимит обычно 100 запросов в минуту
            response = tester.client.get("/api/projects/", headers=auth_headers)
            if response.status_code == 429:  # Rate limit exceeded
                break
        
        # Проверяем, что rate limiting сработал
        assert response.status_code == 429
    
    def test_boundary_concurrent_requests(self, tester, auth_headers):
        """Граничный тест: одновременные запросы"""
        import threading
        import time
        
        results = []
        
        def make_request():
            response = tester.client.get("/api/projects/", headers=auth_headers)
            results.append(response.status_code)
        
        # Создаем 10 одновременных запросов
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        # Проверяем, что все запросы обработаны корректно
        assert len(results) == 10
        assert all(status == 200 for status in results)
    
    def test_boundary_memory_usage(self, tester, auth_headers):
        """Граничный тест: использование памяти"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Создаем много проектов
        for i in range(50):
            project_data = {
                "name": f"Memory Test Project {i}",
                "description": "A" * 100,  # 100 символов
                "tech_stack": {"frontend": "react"}
            }
            
            response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
            assert response.status_code == 201
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Проверяем, что увеличение памяти разумное (менее 100MB)
        assert memory_increase < 100 * 1024 * 1024

class TestPerformanceScenarios:
    """Тесты производительности"""
    
    @pytest.fixture
    def tester(self):
        return CriticalScenarioTester()
    
    @pytest.fixture
    def auth_headers(self, tester):
        return {"Authorization": f"Bearer {tester.test_user_id}"}
    
    def test_performance_large_project_generation(self, tester, auth_headers):
        """Тест производительности: генерация большого проекта"""
        import time
        
        # Создаем проект
        project_data = {
            "name": "Large Performance Test Project",
            "description": "Testing performance with large project",
            "tech_stack": {
                "frontend": "react",
                "backend": "python",
                "database": "postgresql",
                "deployment": "docker"
            }
        }
        
        response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
        assert response.status_code == 201
        project_id = response.json()["id"]
        
        # Засекаем время генерации
        start_time = time.time()
        
        generation_request = {
            "prompt": "Create a comprehensive e-commerce platform with user management, product catalog, shopping cart, payment processing, order management, admin dashboard, and analytics",
            "features": [
                "user_auth", "product_catalog", "shopping_cart", 
                "payment_processing", "order_management", "admin_dashboard", 
                "analytics", "notifications", "search", "recommendations"
            ]
        }
        
        response = tester.client.post(
            f"/api/projects/{project_id}/generate",
            json=generation_request,
            headers=auth_headers
        )
        assert response.status_code == 202
        
        # Ждем завершения генерации
        while True:
            response = tester.client.get(
                f"/api/projects/{project_id}/status",
                headers=auth_headers
            )
            status = response.json()
            
            if status["status"] in ["completed", "error"]:
                break
            
            time.sleep(1)
        
        end_time = time.time()
        generation_time = end_time - start_time
        
        # Проверяем, что генерация завершилась за разумное время (менее 5 минут)
        assert generation_time < 300
        assert status["status"] == "completed"
    
    def test_performance_database_queries(self, tester, auth_headers):
        """Тест производительности: запросы к базе данных"""
        import time
        
        # Создаем много проектов
        start_time = time.time()
        
        for i in range(100):
            project_data = {
                "name": f"Performance Test Project {i}",
                "description": f"Performance test project {i}",
                "tech_stack": {"frontend": "react"}
            }
            
            response = tester.client.post("/api/projects/", json=project_data, headers=auth_headers)
            assert response.status_code == 201
        
        creation_time = time.time() - start_time
        
        # Проверяем, что создание 100 проектов заняло менее 10 секунд
        assert creation_time < 10
        
        # Тестируем получение списка проектов
        start_time = time.time()
        
        response = tester.client.get("/api/projects/", headers=auth_headers)
        assert response.status_code == 200
        
        query_time = time.time() - start_time
        
        # Проверяем, что запрос выполнился менее чем за 1 секунду
        assert query_time < 1

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])