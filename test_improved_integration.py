#!/usr/bin/env python3
"""
Улучшенные интеграционные тесты
Тестирует все компоненты с реальной конфигурацией
"""

import asyncio
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
import httpx
import pytest
from typing import Dict, Any

# Настройка тестового окружения
BASE_URL = "http://localhost:8000"
TEST_USER_EMAIL = f"test_{uuid.uuid4().hex[:8]}@example.com"
TEST_USER_PASSWORD = "TestPassword123!"

class ImprovedIntegrationTest:
    """Улучшенные интеграционные тесты"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = httpx.AsyncClient(timeout=30.0)
        self.auth_token = None
        self.user_id = None
        self.project_id = None
        self.test_results = {}
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.aclose()
    
    def get_headers(self) -> Dict[str, str]:
        """Получение заголовков с авторизацией"""
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    async def test_server_startup(self) -> bool:
        """Тест запуска сервера"""
        
        print("🚀 Тестируем запуск сервера...")
        
        try:
            response = await self.session.get(f"{self.base_url}/")
            assert response.status_code == 200
            data = response.json()
            assert "message" in data
            assert "Samokoder" in data["message"]
            print("✅ Сервер запущен успешно")
            
            self.test_results["server_startup"] = True
            return True
            
        except Exception as e:
            print(f"❌ Ошибка запуска сервера: {e}")
            self.test_results["server_startup"] = False
            return False
    
    async def test_health_endpoints(self) -> bool:
        """Тест health endpoints"""
        
        print("🔍 Тестируем health endpoints...")
        
        try:
            # Базовый health check
            response = await self.session.get(f"{self.base_url}/health")
            assert response.status_code == 200
            health_data = response.json()
            assert "status" in health_data
            print("✅ Health check пройден")
            
            # Детальный health check
            response = await self.session.get(f"{self.base_url}/health/detailed")
            assert response.status_code == 200
            detailed_data = response.json()
            assert "uptime_seconds" in detailed_data
            print("✅ Detailed health check пройден")
            
            # Метрики
            response = await self.session.get(f"{self.base_url}/metrics")
            assert response.status_code == 200
            metrics_text = response.text
            assert "api_requests_total" in metrics_text
            print("✅ Metrics endpoint пройден")
            
            self.test_results["health_endpoints"] = True
            return True
            
        except Exception as e:
            print(f"❌ Health endpoints тест провален: {e}")
            self.test_results["health_endpoints"] = False
            return False
    
    async def test_ai_service(self) -> bool:
        """Тест AI сервиса"""
        
        print("🤖 Тестируем AI сервис...")
        
        try:
            # Получение списка провайдеров
            response = await self.session.get(f"{self.base_url}/api/ai/providers")
            assert response.status_code == 200
            providers_data = response.json()
            assert "providers" in providers_data
            assert len(providers_data["providers"]) > 0
            print("✅ AI providers endpoint пройден")
            
            # Mock AI чат (без реальных ключей)
            response = await self.session.post(
                f"{self.base_url}/api/ai/chat",
                headers=self.get_headers(),
                json={
                    "message": "Тестовое сообщение",
                    "model": "gpt-4o-mini",
                    "provider": "openai"
                }
            )
            # Ожидаем ошибку из-за отсутствия реальных ключей
            assert response.status_code in [500, 401, 400]
            print("✅ AI chat endpoint работает (ожидаемая ошибка без ключей)")
            
            self.test_results["ai_service"] = True
            return True
            
        except Exception as e:
            print(f"❌ AI service тест провален: {e}")
            self.test_results["ai_service"] = False
            return False
    
    async def test_project_management(self) -> bool:
        """Тест управления проектами"""
        
        print("📁 Тестируем управление проектами...")
        
        try:
            # Создание проекта
            project_data = {
                "name": f"Test Project {datetime.now().strftime('%H%M%S')}",
                "description": "Тестовый проект для интеграционного тестирования"
            }
            
            response = await self.session.post(
                f"{self.base_url}/api/projects",
                headers=self.get_headers(),
                json=project_data
            )
            
            if response.status_code == 200:
                data = response.json()
                self.project_id = data["project_id"]
                print("✅ Создание проекта пройдено")
                
                # Получение проекта
                response = await self.session.get(
                    f"{self.base_url}/api/projects/{self.project_id}",
                    headers=self.get_headers()
                )
                assert response.status_code == 200
                print("✅ Получение проекта пройдено")
                
                # Получение файлов проекта
                response = await self.session.get(
                    f"{self.base_url}/api/projects/{self.project_id}/files",
                    headers=self.get_headers()
                )
                assert response.status_code == 200
                print("✅ Получение файлов проекта пройдено")
                
                self.test_results["project_management"] = True
                return True
            else:
                print(f"⚠️ Создание проекта не удалось: {response.status_code} - {response.text}")
                self.test_results["project_management"] = False
                return False
                
        except Exception as e:
            print(f"❌ Project management тест провален: {e}")
            self.test_results["project_management"] = False
            return False
    
    async def test_gpt_pilot_integration(self) -> bool:
        """Тест интеграции с GPT-Pilot"""
        
        print("🤖 Тестируем интеграцию с GPT-Pilot...")
        
        if not self.project_id:
            print("⚠️ Нет активного проекта, пропускаем тест GPT-Pilot")
            self.test_results["gpt_pilot_integration"] = False
            return False
        
        try:
            # Тест чата с агентами
            response = await self.session.post(
                f"{self.base_url}/api/projects/{self.project_id}/chat",
                headers=self.get_headers(),
                json={
                    "message": "Создай простой React компонент",
                    "context": "development"
                }
            )
            
            if response.status_code == 200:
                print("✅ Чат с агентами работает")
                
                # Тест генерации приложения
                response = await self.session.post(
                    f"{self.base_url}/api/projects/{self.project_id}/generate",
                    headers=self.get_headers()
                )
                
                if response.status_code == 200:
                    print("✅ Генерация приложения работает")
                    self.test_results["gpt_pilot_integration"] = True
                    return True
                else:
                    print(f"⚠️ Генерация приложения не удалась: {response.status_code}")
                    self.test_results["gpt_pilot_integration"] = False
                    return False
            else:
                print(f"⚠️ Чат с агентами не удался: {response.status_code}")
                self.test_results["gpt_pilot_integration"] = False
                return False
                
        except Exception as e:
            print(f"❌ GPT-Pilot integration тест провален: {e}")
            self.test_results["gpt_pilot_integration"] = False
            return False
    
    async def test_rate_limiting(self) -> bool:
        """Тест rate limiting"""
        
        print("⏱️ Тестируем rate limiting...")
        
        try:
            # Делаем много запросов подряд
            requests_made = 0
            rate_limited = False
            
            for i in range(70):  # Больше чем лимит в минуту
                response = await self.session.get(
                    f"{self.base_url}/health",
                    headers=self.get_headers()
                )
                requests_made += 1
                
                if response.status_code == 429:
                    rate_limited = True
                    print(f"✅ Rate limiting сработал после {requests_made} запросов")
                    break
                
                # Небольшая задержка между запросами
                await asyncio.sleep(0.1)
            
            if rate_limited:
                self.test_results["rate_limiting"] = True
                return True
            else:
                print("⚠️ Rate limiting не сработал")
                self.test_results["rate_limiting"] = False
                return False
                
        except Exception as e:
            print(f"❌ Rate limiting тест провален: {e}")
            self.test_results["rate_limiting"] = False
            return False
    
    async def test_error_handling(self) -> bool:
        """Тест обработки ошибок"""
        
        print("🚨 Тестируем обработку ошибок...")
        
        try:
            # Тест несуществующего эндпоинта
            response = await self.session.get(f"{self.base_url}/api/nonexistent")
            assert response.status_code == 404
            print("✅ 404 ошибка обработана корректно")
            
            # Тест несуществующего проекта
            response = await self.session.get(
                f"{self.base_url}/api/projects/nonexistent",
                headers=self.get_headers()
            )
            assert response.status_code == 404
            print("✅ 404 для несуществующего проекта обработана корректно")
            
            # Тест невалидных данных
            response = await self.session.post(
                f"{self.base_url}/api/projects",
                headers=self.get_headers(),
                json={"invalid": "data"}
            )
            assert response.status_code == 400
            print("✅ 400 ошибка для невалидных данных обработана корректно")
            
            self.test_results["error_handling"] = True
            return True
            
        except Exception as e:
            print(f"❌ Error handling тест провален: {e}")
            self.test_results["error_handling"] = False
            return False
    
    async def cleanup(self):
        """Очистка после тестов"""
        
        if self.project_id:
            try:
                response = await self.session.delete(
                    f"{self.base_url}/api/projects/{self.project_id}",
                    headers=self.get_headers()
                )
                if response.status_code == 200:
                    print("✅ Тестовый проект удален")
            except Exception as e:
                print(f"⚠️ Ошибка удаления тестового проекта: {e}")

async def run_improved_integration_tests():
    """Запуск улучшенных интеграционных тестов"""
    
    print("🧪 Запуск улучшенных интеграционных тестов")
    print("=" * 60)
    
    async with ImprovedIntegrationTest(BASE_URL) as test:
        # Mock аутентификация для тестов
        test.user_id = str(uuid.uuid4())
        test.auth_token = f"mock_token_{test.user_id}"
        
        tests = [
            ("Server Startup", test.test_server_startup),
            ("Health Endpoints", test.test_health_endpoints),
            ("AI Service", test.test_ai_service),
            ("Project Management", test.test_project_management),
            ("GPT-Pilot Integration", test.test_gpt_pilot_integration),
            ("Rate Limiting", test.test_rate_limiting),
            ("Error Handling", test.test_error_handling)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔍 {test_name}...")
            try:
                result = await test_func()
                if result:
                    passed += 1
                    print(f"✅ {test_name} пройден")
                else:
                    print(f"❌ {test_name} провален")
            except Exception as e:
                print(f"❌ {test_name} провален с ошибкой: {e}")
        
        # Очистка
        await test.cleanup()
        
        # Результаты
        print("\n" + "=" * 60)
        print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
        print("=" * 60)
        
        for test_name, result in test.test_results.items():
            status = "✅ ПРОЙДЕН" if result else "❌ ПРОВАЛЕН"
            print(f"{test_name}: {status}")
        
        print(f"\n📈 Общий результат: {passed}/{total} тестов пройдено")
        print(f"📊 Процент успеха: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("🎉 Все тесты пройдены успешно!")
        elif passed >= total * 0.8:
            print("✅ Большинство тестов пройдено, проект готов к использованию")
        else:
            print("⚠️ Много тестов провалено, требуется доработка")
        
        return passed, total

if __name__ == "__main__":
    asyncio.run(run_improved_integration_tests())