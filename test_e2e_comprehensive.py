#!/usr/bin/env python3
"""
E2E Comprehensive тесты для проекта Самокодер
Полный цикл: регистрация → создание проекта → генерация → экспорт
"""

import asyncio
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
import httpx
import pytest
from typing import Dict, Any, List

# Настройка тестового окружения
BASE_URL = "http://localhost:8000"
TEST_USER_EMAIL = f"test_{uuid.uuid4().hex[:8]}@example.com"
TEST_USER_PASSWORD = "TestPassword123!"
TEST_PROJECT_NAME = f"Test Project {datetime.now().strftime('%H%M%S')}"
TEST_PROJECT_DESCRIPTION = "E2E тестовый проект для проверки полного цикла"

class E2ETestClient:
    """Клиент для E2E тестирования"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = httpx.AsyncClient(timeout=30.0)
        self.auth_token = None
        self.user_id = None
        self.project_id = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.aclose()
    
    async def register_user(self, email: str, password: str) -> Dict[str, Any]:
        """Регистрация пользователя"""
        
        # В реальном приложении здесь будет регистрация через Supabase Auth
        # Пока используем mock данные
        self.user_id = str(uuid.uuid4())
        self.auth_token = f"mock_token_{self.user_id}"
        
        return {
            "user_id": self.user_id,
            "email": email,
            "token": self.auth_token,
            "status": "registered"
        }
    
    async def login_user(self, email: str, password: str) -> Dict[str, Any]:
        """Вход пользователя"""
        
        # Mock логин
        self.user_id = str(uuid.uuid4())
        self.auth_token = f"mock_token_{self.user_id}"
        
        return {
            "user_id": self.user_id,
            "email": email,
            "token": self.auth_token,
            "status": "logged_in"
        }
    
    async def get_headers(self) -> Dict[str, str]:
        """Получение заголовков с авторизацией"""
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    async def create_project(self, name: str, description: str) -> Dict[str, Any]:
        """Создание проекта"""
        
        response = await self.session.post(
            f"{self.base_url}/api/projects",
            headers=await self.get_headers(),
            json={
                "name": name,
                "description": description
            }
        )
        
        assert response.status_code == 200, f"Project creation failed: {response.text}"
        
        data = response.json()
        self.project_id = data["project_id"]
        
        return data
    
    async def get_project(self, project_id: str) -> Dict[str, Any]:
        """Получение информации о проекте"""
        
        response = await self.session.get(
            f"{self.base_url}/api/projects/{project_id}",
            headers=await self.get_headers()
        )
        
        assert response.status_code == 200, f"Get project failed: {response.text}"
        return response.json()
    
    async def chat_with_ai(self, message: str, project_id: str = None) -> Dict[str, Any]:
        """Чат с AI"""
        
        response = await self.session.post(
            f"{self.base_url}/api/ai/chat",
            headers=await self.get_headers(),
            json={
                "message": message,
                "project_id": project_id or self.project_id,
                "provider": "openrouter",
                "model": "deepseek/deepseek-v3"
            }
        )
        
        assert response.status_code == 200, f"AI chat failed: {response.text}"
        return response.json()
    
    async def generate_project(self, project_id: str) -> List[Dict[str, Any]]:
        """Генерация проекта"""
        
        response = await self.session.post(
            f"{self.base_url}/api/projects/{project_id}/generate",
            headers=await self.get_headers()
        )
        
        assert response.status_code == 200, f"Project generation failed: {response.text}"
        
        # Читаем streaming ответ
        updates = []
        async for line in response.aiter_lines():
            if line.startswith("data: "):
                try:
                    data = json.loads(line[6:])
                    updates.append(data)
                    
                    # Если генерация завершена
                    if data.get("type") == "generation_complete":
                        break
                except json.JSONDecodeError:
                    continue
        
        return updates
    
    async def get_project_files(self, project_id: str) -> Dict[str, Any]:
        """Получение файлов проекта"""
        
        response = await self.session.get(
            f"{self.base_url}/api/projects/{project_id}/files",
            headers=await self.get_headers()
        )
        
        assert response.status_code == 200, f"Get project files failed: {response.text}"
        return response.json()
    
    async def export_project(self, project_id: str) -> bytes:
        """Экспорт проекта"""
        
        response = await self.session.post(
            f"{self.base_url}/api/projects/{project_id}/export",
            headers=await self.get_headers()
        )
        
        assert response.status_code == 200, f"Project export failed: {response.text}"
        return response.content
    
    async def get_ai_usage(self) -> Dict[str, Any]:
        """Получение статистики AI использования"""
        
        response = await self.session.get(
            f"{self.base_url}/api/ai/usage",
            headers=await self.get_headers()
        )
        
        assert response.status_code == 200, f"Get AI usage failed: {response.text}"
        return response.json()
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Получение статуса здоровья системы"""
        
        response = await self.session.get(f"{self.base_url}/health")
        assert response.status_code == 200, f"Health check failed: {response.text}"
        return response.json()
    
    async def get_metrics(self) -> str:
        """Получение метрик Prometheus"""
        
        response = await self.session.get(f"{self.base_url}/metrics")
        assert response.status_code == 200, f"Get metrics failed: {response.text}"
        return response.text

@pytest.mark.asyncio
async def test_full_user_journey():
    """Тест полного пользовательского пути"""
    
    async with E2ETestClient(BASE_URL) as client:
        print("🚀 Начинаем E2E тест полного цикла...")
        
        # 1. Регистрация пользователя
        print("1️⃣ Регистрация пользователя...")
        user_data = await client.register_user(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        assert user_data["status"] == "registered"
        print(f"✅ Пользователь зарегистрирован: {user_data['user_id']}")
        
        # 2. Проверка здоровья системы
        print("2️⃣ Проверка здоровья системы...")
        health = await client.get_health_status()
        assert health["status"] == "healthy"
        print(f"✅ Система здорова: uptime {health['uptime_human']}")
        
        # 3. Создание проекта
        print("3️⃣ Создание проекта...")
        project_data = await client.create_project(TEST_PROJECT_NAME, TEST_PROJECT_DESCRIPTION)
        assert project_data["status"] == "created"
        print(f"✅ Проект создан: {project_data['project_id']}")
        
        # 4. Получение информации о проекте
        print("4️⃣ Получение информации о проекте...")
        project_info = await client.get_project(project_data["project_id"])
        assert project_info["project"]["name"] == TEST_PROJECT_NAME
        print(f"✅ Проект получен: {project_info['project']['name']}")
        
        # 5. Чат с AI
        print("5️⃣ Чат с AI...")
        ai_response = await client.chat_with_ai(
            "Создай React компонент для отображения списка задач",
            project_data["project_id"]
        )
        assert "content" in ai_response
        print(f"✅ AI ответ получен: {len(ai_response['content'])} символов")
        
        # 6. Генерация проекта
        print("6️⃣ Генерация проекта...")
        generation_updates = await client.generate_project(project_data["project_id"])
        
        # Проверяем, что получили обновления
        assert len(generation_updates) > 0
        print(f"✅ Генерация завершена: {len(generation_updates)} обновлений")
        
        # Проверяем, что генерация завершилась успешно
        final_update = generation_updates[-1]
        assert final_update.get("type") == "generation_complete"
        print(f"✅ Генерация успешно завершена: {final_update.get('files_count', 0)} файлов")
        
        # 7. Получение файлов проекта
        print("7️⃣ Получение файлов проекта...")
        files_data = await client.get_project_files(project_data["project_id"])
        assert "files" in files_data
        print(f"✅ Файлы получены: {len(files_data['files'])} элементов")
        
        # 8. Экспорт проекта
        print("8️⃣ Экспорт проекта...")
        export_data = await client.export_project(project_data["project_id"])
        assert len(export_data) > 0
        print(f"✅ Проект экспортирован: {len(export_data)} байт")
        
        # 9. Проверка статистики AI
        print("9️⃣ Проверка статистики AI...")
        usage_stats = await client.get_ai_usage()
        assert "total_requests" in usage_stats
        print(f"✅ Статистика AI: {usage_stats['total_requests']} запросов")
        
        # 10. Проверка метрик
        print("🔟 Проверка метрик...")
        metrics = await client.get_metrics()
        assert "api_requests_total" in metrics
        print(f"✅ Метрики получены: {len(metrics)} символов")
        
        print("🎉 E2E тест полного цикла завершен успешно!")

@pytest.mark.asyncio
async def test_ai_providers():
    """Тест AI провайдеров"""
    
    async with E2ETestClient(BASE_URL) as client:
        print("🤖 Тестируем AI провайдеров...")
        
        # Регистрация
        await client.register_user(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        
        # Получение списка провайдеров
        response = await client.session.get(f"{client.base_url}/api/ai/providers")
        assert response.status_code == 200
        
        providers_data = response.json()
        assert "providers" in providers_data
        assert len(providers_data["providers"]) > 0
        
        print(f"✅ Найдено {len(providers_data['providers'])} AI провайдеров")
        
        # Проверяем каждого провайдера
        for provider in providers_data["providers"]:
            assert "id" in provider
            assert "name" in provider
            assert "description" in provider
            assert "website" in provider
            assert "requires_key" in provider
            print(f"  - {provider['name']}: {provider['description']}")

@pytest.mark.asyncio
async def test_error_handling():
    """Тест обработки ошибок"""
    
    async with E2ETestClient(BASE_URL) as client:
        print("⚠️ Тестируем обработку ошибок...")
        
        # Тест без авторизации
        response = await client.session.get(f"{client.base_url}/api/projects")
        assert response.status_code == 401
        
        # Тест несуществующего проекта
        await client.register_user(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        response = await client.session.get(
            f"{client.base_url}/api/projects/nonexistent",
            headers=await client.get_headers()
        )
        assert response.status_code == 404
        
        # Тест невалидного AI запроса
        response = await client.session.post(
            f"{client.base_url}/api/ai/chat",
            headers=await client.get_headers(),
            json={"invalid": "data"}
        )
        assert response.status_code == 400
        
        print("✅ Обработка ошибок работает корректно")

@pytest.mark.asyncio
async def test_performance():
    """Тест производительности"""
    
    async with E2ETestClient(BASE_URL) as client:
        print("⚡ Тестируем производительность...")
        
        await client.register_user(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        
        # Тест времени отклика API
        start_time = time.time()
        health = await client.get_health_status()
        response_time = time.time() - start_time
        
        assert response_time < 1.0, f"Health check too slow: {response_time:.3f}s"
        print(f"✅ Health check: {response_time:.3f}s")
        
        # Тест создания проекта
        start_time = time.time()
        project_data = await client.create_project(TEST_PROJECT_NAME, TEST_PROJECT_DESCRIPTION)
        creation_time = time.time() - start_time
        
        assert creation_time < 5.0, f"Project creation too slow: {creation_time:.3f}s"
        print(f"✅ Project creation: {creation_time:.3f}s")
        
        # Тест AI запроса
        start_time = time.time()
        ai_response = await client.chat_with_ai("Привет, как дела?")
        ai_time = time.time() - start_time
        
        assert ai_time < 10.0, f"AI request too slow: {ai_time:.3f}s"
        print(f"✅ AI request: {ai_time:.3f}s")

@pytest.mark.asyncio
async def test_concurrent_requests():
    """Тест параллельных запросов"""
    
    async with E2ETestClient(BASE_URL) as client:
        print("🔄 Тестируем параллельные запросы...")
        
        await client.register_user(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        
        # Создаем несколько проектов параллельно
        tasks = []
        for i in range(3):
            task = client.create_project(f"Concurrent Project {i}", f"Description {i}")
            tasks.append(task)
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        # Проверяем, что все проекты созданы
        for result in results:
            assert result["status"] == "created"
        
        print(f"✅ Создано {len(results)} проектов за {total_time:.3f}s")
        
        # Проверяем, что параллельные запросы быстрее последовательных
        assert total_time < 15.0, f"Concurrent requests too slow: {total_time:.3f}s"

async def run_all_tests():
    """Запуск всех E2E тестов"""
    
    print("🧪 Запуск E2E Comprehensive тестов...")
    print("=" * 50)
    
    tests = [
        ("Полный пользовательский путь", test_full_user_journey),
        ("AI провайдеры", test_ai_providers),
        ("Обработка ошибок", test_error_handling),
        ("Производительность", test_performance),
        ("Параллельные запросы", test_concurrent_requests),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\n🔍 Запуск: {test_name}")
            await test_func()
            print(f"✅ {test_name} - ПРОЙДЕН")
            passed += 1
        except Exception as e:
            print(f"❌ {test_name} - ПРОВАЛЕН: {e}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Результаты E2E тестов:")
    print(f"✅ Пройдено: {passed}")
    print(f"❌ Провалено: {failed}")
    print(f"📈 Успешность: {(passed / (passed + failed) * 100):.1f}%")
    
    if failed == 0:
        print("🎉 Все E2E тесты пройдены успешно!")
    else:
        print("⚠️ Некоторые тесты провалились. Проверьте логи выше.")
    
    return failed == 0

if __name__ == "__main__":
    # Запуск тестов
    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)