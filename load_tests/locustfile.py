"""
Load tests для Самокодер API
Использует Locust для нагрузочного тестирования
"""

from locust import HttpUser, task, between
import json
import uuid
import random
from datetime import datetime

class SamokoderUser(HttpUser):
    """Пользователь Самокодер для нагрузочного тестирования"""
    
    wait_time = between(1, 3)  # Задержка между запросами 1-3 секунды
    
    def on_start(self):
        """Инициализация пользователя"""
        self.user_id = str(uuid.uuid4())
        self.auth_token = f"mock_token_{self.user_id}"
        self.project_id = None
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    @task(10)
    def health_check(self):
        """Проверка health endpoint (высокая частота)"""
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(5)
    def get_ai_providers(self):
        """Получение списка AI провайдеров"""
        with self.client.get("/api/ai/providers", catch_response=True) as response:
            if response.status_code == 200:
                data = response.json()
                if "providers" in data and len(data["providers"]) > 0:
                    response.success()
                else:
                    response.failure("No providers in response")
            else:
                response.failure(f"AI providers failed: {response.status_code}")
    
    @task(3)
    def create_project(self):
        """Создание проекта"""
        project_data = {
            "name": f"Load Test Project {datetime.now().strftime('%H%M%S')}",
            "description": f"Проект для нагрузочного тестирования {uuid.uuid4().hex[:8]}"
        }
        
        with self.client.post(
            "/api/projects",
            headers=self.headers,
            json=project_data,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "project_id" in data:
                    self.project_id = data["project_id"]
                    response.success()
                else:
                    response.failure("No project_id in response")
            else:
                response.failure(f"Project creation failed: {response.status_code}")
    
    @task(2)
    def get_project(self):
        """Получение проекта"""
        if not self.project_id:
            return
        
        with self.client.get(
            f"/api/projects/{self.project_id}",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Get project failed: {response.status_code}")
    
    @task(2)
    def get_project_files(self):
        """Получение файлов проекта"""
        if not self.project_id:
            return
        
        with self.client.get(
            f"/api/projects/{self.project_id}/files",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Get project files failed: {response.status_code}")
    
    @task(1)
    def chat_with_agents(self):
        """Чат с агентами GPT-Pilot"""
        if not self.project_id:
            return
        
        messages = [
            "Создай простой React компонент",
            "Добавь TypeScript типы",
            "Создай API endpoint для пользователей",
            "Добавь тесты для компонента",
            "Оптимизируй производительность"
        ]
        
        message = random.choice(messages)
        
        with self.client.post(
            f"/api/projects/{self.project_id}/chat",
            headers=self.headers,
            json={
                "message": message,
                "context": "development"
            },
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Chat with agents failed: {response.status_code}")
    
    @task(1)
    def generate_app(self):
        """Генерация приложения"""
        if not self.project_id:
            return
        
        with self.client.post(
            f"/api/projects/{self.project_id}/generate",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"App generation failed: {response.status_code}")
    
    @task(5)
    def ai_chat(self):
        """AI чат (может быть медленным)"""
        messages = [
            "Привет! Как дела?",
            "Объясни, что такое React",
            "Помоги с кодом на Python",
            "Что такое машинное обучение?",
            "Создай простой алгоритм сортировки"
        ]
        
        message = random.choice(messages)
        
        with self.client.post(
            "/api/ai/chat",
            headers=self.headers,
            json={
                "message": message,
                "model": "gpt-4o-mini",
                "provider": "openai"
            },
            catch_response=True
        ) as response:
            # Ожидаем ошибку из-за отсутствия реальных ключей
            if response.status_code in [500, 401, 400]:
                response.success()  # Это ожидаемая ошибка
            else:
                response.failure(f"Unexpected AI chat response: {response.status_code}")
    
    @task(3)
    def get_metrics(self):
        """Получение метрик"""
        with self.client.get("/metrics", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Metrics failed: {response.status_code}")
    
    @task(1)
    def rate_limit_test(self):
        """Тест rate limiting (быстрые запросы)"""
        # Делаем несколько быстрых запросов подряд
        for _ in range(5):
            with self.client.get("/health", catch_response=True) as response:
                if response.status_code == 429:
                    response.success()  # Rate limit сработал
                    return
                elif response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Unexpected response: {response.status_code}")

class HighLoadUser(HttpUser):
    """Пользователь с высокой нагрузкой"""
    
    wait_time = between(0.1, 0.5)  # Очень короткие задержки
    
    @task(20)
    def rapid_health_checks(self):
        """Быстрые проверки health"""
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(10)
    def rapid_metrics(self):
        """Быстрые запросы метрик"""
        with self.client.get("/metrics", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Metrics failed: {response.status_code}")

# Конфигурация тестов
class WebsiteUser(SamokoderUser):
    """Основной пользователь для тестирования"""
    weight = 3

class HighLoadUser(HighLoadUser):
    """Пользователь с высокой нагрузкой"""
    weight = 1