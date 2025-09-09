"""
Load тесты для проекта Самокодер
Тестирование производительности под нагрузкой
"""

from locust import HttpUser, task, between
import json
import uuid
import random

class SamokoderUser(HttpUser):
    """Пользователь для load тестирования"""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Инициализация пользователя"""
        self.user_id = str(uuid.uuid4())
        self.auth_token = f"mock_token_{self.user_id}"
        self.project_id = None
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    @task(3)
    def health_check(self):
        """Проверка здоровья системы"""
        self.client.get("/health")
    
    @task(2)
    def get_metrics(self):
        """Получение метрик"""
        self.client.get("/metrics")
    
    @task(1)
    def create_project(self):
        """Создание проекта"""
        project_data = {
            "name": f"Load Test Project {uuid.uuid4().hex[:8]}",
            "description": "Проект для load тестирования"
        }
        
        response = self.client.post(
            "/api/projects",
            headers=self.headers,
            json=project_data
        )
        
        if response.status_code == 200:
            data = response.json()
            self.project_id = data.get("project_id")
    
    @task(2)
    def get_projects(self):
        """Получение списка проектов"""
        self.client.get("/api/projects", headers=self.headers)
    
    @task(1)
    def chat_with_ai(self):
        """Чат с AI"""
        if not self.project_id:
            return
        
        messages = [
            "Создай React компонент",
            "Добавь стили CSS",
            "Создай API endpoint",
            "Настрой базу данных",
            "Добавь аутентификацию"
        ]
        
        ai_data = {
            "message": random.choice(messages),
            "project_id": self.project_id,
            "provider": "openrouter",
            "model": "deepseek/deepseek-v3"
        }
        
        self.client.post(
            "/api/ai/chat",
            headers=self.headers,
            json=ai_data
        )
    
    @task(1)
    def get_project_files(self):
        """Получение файлов проекта"""
        if not self.project_id:
            return
        
        self.client.get(
            f"/api/projects/{self.project_id}/files",
            headers=self.headers
        )
    
    @task(1)
    def export_project(self):
        """Экспорт проекта"""
        if not self.project_id:
            return
        
        self.client.post(
            f"/api/projects/{self.project_id}/export",
            headers=self.headers
        )
    
    @task(1)
    def get_ai_usage(self):
        """Получение статистики AI"""
        self.client.get("/api/ai/usage", headers=self.headers)
    
    @task(1)
    def get_ai_providers(self):
        """Получение списка AI провайдеров"""
        self.client.get("/api/ai/providers")

class HighLoadUser(HttpUser):
    """Пользователь для высоконагруженного тестирования"""
    
    wait_time = between(0.1, 0.5)
    weight = 1  # Меньше пользователей этого типа
    
    def on_start(self):
        """Инициализация пользователя"""
        self.user_id = str(uuid.uuid4())
        self.auth_token = f"mock_token_{self.user_id}"
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    @task(10)
    def rapid_health_checks(self):
        """Быстрые проверки здоровья"""
        self.client.get("/health")
    
    @task(5)
    def rapid_metrics(self):
        """Быстрое получение метрик"""
        self.client.get("/metrics")
    
    @task(2)
    def rapid_ai_chat(self):
        """Быстрый AI чат"""
        ai_data = {
            "message": "Быстрый тест",
            "provider": "openrouter",
            "model": "deepseek/deepseek-v3"
        }
        
        self.client.post(
            "/api/ai/chat",
            headers=self.headers,
            json=ai_data
        )

# Конфигурация для разных сценариев тестирования
class TestConfig:
    """Конфигурация тестов"""
    
    @staticmethod
    def get_normal_load_config():
        """Конфигурация для нормальной нагрузки"""
        return {
            "users": 10,
            "spawn_rate": 2,
            "run_time": "2m"
        }
    
    @staticmethod
    def get_high_load_config():
        """Конфигурация для высокой нагрузки"""
        return {
            "users": 50,
            "spawn_rate": 5,
            "run_time": "5m"
        }
    
    @staticmethod
    def get_stress_test_config():
        """Конфигурация для стресс-тестирования"""
        return {
            "users": 100,
            "spawn_rate": 10,
            "run_time": "10m"
        }

# Запуск тестов:
# locust -f load_tests/locustfile.py --host=http://localhost:8000
# 
# Для разных сценариев:
# locust -f load_tests/locustfile.py --host=http://localhost:8000 -u 10 -r 2 -t 2m
# locust -f load_tests/locustfile.py --host=http://localhost:8000 -u 50 -r 5 -t 5m
# locust -f load_tests/locustfile.py --host=http://localhost:8000 -u 100 -r 10 -t 10m