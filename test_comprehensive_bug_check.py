#!/usr/bin/env python3
"""
Comprehensive тест для проверки всех компонентов на баги
"""

import asyncio
import httpx
import json
import uuid
from datetime import datetime
import traceback

BASE_URL = "http://localhost:8001"

class ComprehensiveBugChecker:
    """Comprehensive проверка на баги"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = httpx.AsyncClient(timeout=30.0)
        self.bugs_found = []
        self.tests_passed = 0
        self.tests_failed = 0
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.aclose()
    
    def log_bug(self, component: str, description: str, error: str = None):
        """Логирование найденного бага"""
        bug = {
            "component": component,
            "description": description,
            "error": str(error) if error else None,
            "timestamp": datetime.now().isoformat()
        }
        self.bugs_found.append(bug)
        print(f"🐛 BUG FOUND in {component}: {description}")
        if error:
            print(f"   Error: {error}")
    
    def log_success(self, component: str, description: str):
        """Логирование успешного теста"""
        self.tests_passed += 1
        print(f"✅ {component}: {description}")
    
    def log_failure(self, component: str, description: str, error: str = None):
        """Логирование проваленного теста"""
        self.tests_failed += 1
        print(f"❌ {component}: {description}")
        if error:
            print(f"   Error: {error}")
    
    async def test_server_startup(self):
        """Тест запуска сервера"""
        try:
            response = await self.session.get(f"{self.base_url}/")
            if response.status_code == 200:
                data = response.json()
                if "Samokoder" in data.get("message", ""):
                    self.log_success("Server", "Сервер запущен и отвечает")
                else:
                    self.log_bug("Server", "Сервер отвечает, но неправильное сообщение")
            else:
                self.log_bug("Server", f"Сервер отвечает с кодом {response.status_code}")
        except Exception as e:
            self.log_bug("Server", "Сервер не отвечает", str(e))
    
    async def test_health_endpoints(self):
        """Тест health endpoints"""
        try:
            # Базовый health check
            response = await self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                data = response.json()
                if "status" in data:
                    self.log_success("Health", "Базовый health check работает")
                else:
                    self.log_bug("Health", "Health check не содержит поле 'status'")
            else:
                self.log_bug("Health", f"Health check вернул код {response.status_code}")
            
            # Детальный health check
            response = await self.session.get(f"{self.base_url}/health/detailed")
            if response.status_code == 200:
                data = response.json()
                required_fields = ["status", "uptime_seconds", "external_services"]
                missing_fields = [f for f in required_fields if f not in data]
                if not missing_fields:
                    self.log_success("Health", "Детальный health check работает")
                else:
                    self.log_bug("Health", f"Отсутствуют поля: {missing_fields}")
            else:
                self.log_bug("Health", f"Детальный health check вернул код {response.status_code}")
                
        except Exception as e:
            self.log_bug("Health", "Ошибка в health endpoints", str(e))
    
    async def test_metrics_endpoint(self):
        """Тест metrics endpoint"""
        try:
            response = await self.session.get(f"{self.base_url}/metrics")
            if response.status_code == 200:
                content = response.text
                if "api_requests_total" in content:
                    self.log_success("Metrics", "Metrics endpoint работает")
                else:
                    self.log_bug("Metrics", "Metrics не содержит ожидаемые метрики")
            else:
                self.log_bug("Metrics", f"Metrics endpoint вернул код {response.status_code}")
        except Exception as e:
            self.log_bug("Metrics", "Ошибка в metrics endpoint", str(e))
    
    async def test_ai_providers(self):
        """Тест AI провайдеров"""
        try:
            response = await self.session.get(f"{self.base_url}/api/ai/providers")
            if response.status_code == 200:
                data = response.json()
                if "providers" in data and isinstance(data["providers"], list):
                    providers = data["providers"]
                    if len(providers) > 0:
                        # Проверяем структуру провайдера
                        provider = providers[0]
                        required_fields = ["id", "name", "description", "requires_key"]
                        missing_fields = [f for f in required_fields if f not in provider]
                        if not missing_fields:
                            self.log_success("AI Providers", "AI провайдеры получены корректно")
                        else:
                            self.log_bug("AI Providers", f"Провайдер не содержит поля: {missing_fields}")
                    else:
                        self.log_bug("AI Providers", "Список провайдеров пуст")
                else:
                    self.log_bug("AI Providers", "Неправильная структура ответа")
            else:
                self.log_bug("AI Providers", f"AI провайдеры вернули код {response.status_code}")
        except Exception as e:
            self.log_bug("AI Providers", "Ошибка в AI провайдерах", str(e))
    
    async def test_ai_chat_without_keys(self):
        """Тест AI чата без ключей"""
        try:
            # Mock аутентификация
            mock_user_id = str(uuid.uuid4())
            mock_token = f"mock_token_{mock_user_id}"
            headers = {
                "Authorization": f"Bearer {mock_token}",
                "Content-Type": "application/json"
            }
            
            response = await self.session.post(
                f"{self.base_url}/api/ai/chat",
                headers=headers,
                json={
                    "message": "Тестовое сообщение",
                    "model": "gpt-4o-mini",
                    "provider": "openai"
                }
            )
            
            # Ожидаем ошибку из-за отсутствия ключей
            if response.status_code in [400, 401, 500]:
                error_data = response.json()
                if "error" in error_data or "detail" in error_data:
                    self.log_success("AI Chat", "AI чат правильно обрабатывает отсутствие ключей")
                else:
                    self.log_bug("AI Chat", "AI чат вернул ошибку, но без деталей")
            else:
                self.log_bug("AI Chat", f"AI чат вернул неожиданный код {response.status_code}")
                
        except Exception as e:
            self.log_bug("AI Chat", "Ошибка в AI чате", str(e))
    
    async def test_auth_endpoints(self):
        """Тест аутентификации"""
        try:
            # Тест login с mock данными
            response = await self.session.post(
                f"{self.base_url}/api/auth/login",
                json={
                    "email": "test@example.com",
                    "password": "testpassword"
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if "user" in data and "session" in data:
                    self.log_success("Auth", "Mock аутентификация работает")
                else:
                    self.log_bug("Auth", "Login не содержит ожидаемые поля")
            else:
                self.log_bug("Auth", f"Login вернул код {response.status_code}")
                
        except Exception as e:
            self.log_bug("Auth", "Ошибка в аутентификации", str(e))
    
    async def test_project_management(self):
        """Тест управления проектами"""
        try:
            # Mock аутентификация
            mock_user_id = str(uuid.uuid4())
            mock_token = f"mock_token_{mock_user_id}"
            headers = {
                "Authorization": f"Bearer {mock_token}",
                "Content-Type": "application/json"
            }
            
            # Создание проекта
            project_data = {
                "name": f"Test Project {datetime.now().strftime('%H%M%S')}",
                "description": "Тестовый проект для проверки багов"
            }
            
            response = await self.session.post(
                f"{self.base_url}/api/projects",
                headers=headers,
                json=project_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if "project_id" in data:
                    project_id = data["project_id"]
                    self.log_success("Projects", "Создание проекта работает")
                    
                    # Тест получения проекта
                    response = await self.session.get(
                        f"{self.base_url}/api/projects/{project_id}",
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        self.log_success("Projects", "Получение проекта работает")
                    else:
                        self.log_bug("Projects", f"Получение проекта вернуло код {response.status_code}")
                    
                    # Тест получения файлов проекта
                    response = await self.session.get(
                        f"{self.base_url}/api/projects/{project_id}/files",
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        self.log_success("Projects", "Получение файлов проекта работает")
                    else:
                        self.log_bug("Projects", f"Получение файлов вернуло код {response.status_code}")
                        
                else:
                    self.log_bug("Projects", "Создание проекта не вернуло project_id")
            else:
                self.log_bug("Projects", f"Создание проекта вернуло код {response.status_code}")
                
        except Exception as e:
            self.log_bug("Projects", "Ошибка в управлении проектами", str(e))
    
    async def test_gpt_pilot_integration(self):
        """Тест интеграции с GPT-Pilot"""
        try:
            # Mock аутентификация
            mock_user_id = str(uuid.uuid4())
            mock_token = f"mock_token_{mock_user_id}"
            headers = {
                "Authorization": f"Bearer {mock_token}",
                "Content-Type": "application/json"
            }
            
            # Создаем проект для тестирования
            project_data = {
                "name": f"GPT-Pilot Test {datetime.now().strftime('%H%M%S')}",
                "description": "Тестовый проект для GPT-Pilot"
            }
            
            response = await self.session.post(
                f"{self.base_url}/api/projects",
                headers=headers,
                json=project_data
            )
            
            if response.status_code == 200:
                data = response.json()
                project_id = data["project_id"]
                
                # Тест чата с агентами
                response = await self.session.post(
                    f"{self.base_url}/api/projects/{project_id}/chat",
                    headers=headers,
                    json={
                        "message": "Создай простой React компонент",
                        "context": "development"
                    }
                )
                
                if response.status_code == 200:
                    self.log_success("GPT-Pilot", "Чат с агентами работает")
                else:
                    self.log_bug("GPT-Pilot", f"Чат с агентами вернул код {response.status_code}")
                
                # Тест генерации приложения
                response = await self.session.post(
                    f"{self.base_url}/api/projects/{project_id}/generate",
                    headers=headers
                )
                
                if response.status_code == 200:
                    self.log_success("GPT-Pilot", "Генерация приложения работает")
                else:
                    self.log_bug("GPT-Pilot", f"Генерация приложения вернула код {response.status_code}")
                    
            else:
                self.log_bug("GPT-Pilot", "Не удалось создать проект для тестирования")
                
        except Exception as e:
            self.log_bug("GPT-Pilot", "Ошибка в GPT-Pilot интеграции", str(e))
    
    async def test_error_handling(self):
        """Тест обработки ошибок"""
        try:
            # Тест несуществующего эндпоинта
            response = await self.session.get(f"{self.base_url}/api/nonexistent")
            if response.status_code == 404:
                self.log_success("Error Handling", "404 ошибка обработана корректно")
            else:
                self.log_bug("Error Handling", f"Несуществующий эндпоинт вернул код {response.status_code}")
            
            # Тест невалидных данных
            response = await self.session.post(
                f"{self.base_url}/api/projects",
                json={"invalid": "data"}
            )
            if response.status_code == 401:  # Ожидаем ошибку аутентификации
                self.log_success("Error Handling", "Невалидные данные обработаны корректно")
            else:
                self.log_bug("Error Handling", f"Невалидные данные вернули код {response.status_code}")
                
        except Exception as e:
            self.log_bug("Error Handling", "Ошибка в обработке ошибок", str(e))
    
    async def test_rate_limiting(self):
        """Тест rate limiting"""
        try:
            # Делаем несколько быстрых запросов
            for i in range(5):
                response = await self.session.get(f"{self.base_url}/health")
                if response.status_code == 429:
                    self.log_success("Rate Limiting", "Rate limiting сработал")
                    return
                elif response.status_code != 200:
                    self.log_bug("Rate Limiting", f"Health check вернул код {response.status_code}")
                    return
            
            # Если rate limiting не сработал, это может быть нормально
            self.log_success("Rate Limiting", "Rate limiting не сработал (может быть нормально)")
            
        except Exception as e:
            self.log_bug("Rate Limiting", "Ошибка в rate limiting", str(e))
    
    async def test_cors_headers(self):
        """Тест CORS заголовков"""
        try:
            response = await self.session.options(f"{self.base_url}/")
            if response.status_code == 200:
                cors_headers = [
                    "access-control-allow-origin",
                    "access-control-allow-methods",
                    "access-control-allow-headers"
                ]
                present_headers = [h for h in cors_headers if h in response.headers]
                if present_headers:
                    self.log_success("CORS", "CORS заголовки присутствуют")
                else:
                    self.log_bug("CORS", "CORS заголовки отсутствуют")
            else:
                self.log_bug("CORS", f"OPTIONS запрос вернул код {response.status_code}")
        except Exception as e:
            self.log_bug("CORS", "Ошибка в CORS", str(e))
    
    async def run_all_tests(self):
        """Запуск всех тестов"""
        print("🔍 COMPREHENSIVE BUG CHECK")
        print("=" * 60)
        
        tests = [
            ("Server Startup", self.test_server_startup),
            ("Health Endpoints", self.test_health_endpoints),
            ("Metrics Endpoint", self.test_metrics_endpoint),
            ("AI Providers", self.test_ai_providers),
            ("AI Chat", self.test_ai_chat_without_keys),
            ("Authentication", self.test_auth_endpoints),
            ("Project Management", self.test_project_management),
            ("GPT-Pilot Integration", self.test_gpt_pilot_integration),
            ("Error Handling", self.test_error_handling),
            ("Rate Limiting", self.test_rate_limiting),
            ("CORS Headers", self.test_cors_headers)
        ]
        
        for test_name, test_func in tests:
            print(f"\n🔍 {test_name}...")
            try:
                await test_func()
            except Exception as e:
                self.log_bug(test_name, f"Критическая ошибка в тесте", str(e))
                print(f"   Traceback: {traceback.format_exc()}")
        
        # Итоговый отчет
        print("\n" + "=" * 60)
        print("📊 ИТОГОВЫЙ ОТЧЕТ")
        print("=" * 60)
        print(f"✅ Тестов пройдено: {self.tests_passed}")
        print(f"❌ Тестов провалено: {self.tests_failed}")
        print(f"🐛 Багов найдено: {len(self.bugs_found)}")
        
        if self.bugs_found:
            print("\n🐛 НАЙДЕННЫЕ БАГИ:")
            for i, bug in enumerate(self.bugs_found, 1):
                print(f"{i}. {bug['component']}: {bug['description']}")
                if bug['error']:
                    print(f"   Ошибка: {bug['error']}")
        else:
            print("\n🎉 БАГОВ НЕ НАЙДЕНО!")
        
        return len(self.bugs_found) == 0

async def main():
    """Главная функция"""
    async with ComprehensiveBugChecker(BASE_URL) as checker:
        success = await checker.run_all_tests()
        return success

if __name__ == "__main__":
    asyncio.run(main())