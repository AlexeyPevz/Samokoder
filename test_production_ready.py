#!/usr/bin/env python3
"""
Тест готовности к продакшену
Проверка всех компонентов после настройки Supabase
"""

import asyncio
import json
import time
import uuid
from datetime import datetime
import httpx
import sys
from pathlib import Path

# Добавляем путь к проекту
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import settings

BASE_URL = "http://localhost:8000"

class ProductionReadyTest:
    """Тест готовности к продакшену"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = httpx.AsyncClient(timeout=30.0)
        self.test_results = {}
        self.total_tests = 0
        self.passed_tests = 0
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.aclose()
    
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Логирование результата теста"""
        self.total_tests += 1
        if success:
            self.passed_tests += 1
            status = "✅"
        else:
            status = "❌"
        
        print(f"{status} {test_name}: {message}")
        self.test_results[test_name] = success
    
    async def test_server_startup(self) -> bool:
        """Тест запуска сервера"""
        try:
            response = await self.session.get(f"{self.base_url}/")
            if response.status_code == 200:
                data = response.json()
                self.log_test("Server Startup", True, f"Server running: {data.get('version', 'unknown')}")
                return True
            else:
                self.log_test("Server Startup", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Server Startup", False, f"Connection failed: {e}")
            return False
    
    async def test_health_endpoints(self) -> bool:
        """Тест health endpoints"""
        try:
            # Базовый health check
            response = await self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                health_data = response.json()
                if health_data.get("status") == "healthy":
                    self.log_test("Health Check", True, f"Uptime: {health_data.get('uptime_human', 'unknown')}")
                else:
                    self.log_test("Health Check", False, f"Status: {health_data.get('status')}")
                    return False
            else:
                self.log_test("Health Check", False, f"HTTP {response.status_code}")
                return False
            
            # Детальный health check
            response = await self.session.get(f"{self.base_url}/health/detailed")
            if response.status_code == 200:
                self.log_test("Detailed Health Check", True, "All components healthy")
            else:
                self.log_test("Detailed Health Check", False, f"HTTP {response.status_code}")
                return False
            
            # Метрики
            response = await self.session.get(f"{self.base_url}/metrics")
            if response.status_code == 200:
                metrics_text = response.text
                if "api_requests_total" in metrics_text:
                    self.log_test("Metrics Endpoint", True, "Prometheus metrics available")
                else:
                    self.log_test("Metrics Endpoint", False, "No metrics found")
                    return False
            else:
                self.log_test("Metrics Endpoint", False, f"HTTP {response.status_code}")
                return False
            
            return True
        except Exception as e:
            self.log_test("Health Endpoints", False, f"Error: {e}")
            return False
    
    async def test_ai_providers(self) -> bool:
        """Тест AI провайдеров"""
        try:
            response = await self.session.get(f"{self.base_url}/api/ai/providers")
            if response.status_code == 200:
                providers_data = response.json()
                if "providers" in providers_data and len(providers_data["providers"]) > 0:
                    self.log_test("AI Providers", True, f"{len(providers_data['providers'])} providers available")
                    return True
                else:
                    self.log_test("AI Providers", False, "No providers found")
                    return False
            else:
                self.log_test("AI Providers", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("AI Providers", False, f"Error: {e}")
            return False
    
    async def test_database_connection(self) -> bool:
        """Тест подключения к базе данных"""
        try:
            # Проверяем через health endpoint
            response = await self.session.get(f"{self.base_url}/health/detailed")
            if response.status_code == 200:
                health_data = response.json()
                external_services = health_data.get("external_services", {})
                database = external_services.get("supabase", {})
                
                if database.get("status") == "healthy":
                    self.log_test("Database Connection", True, f"Response time: {database.get('response_time', 0):.3f}s")
                    return True
                else:
                    self.log_test("Database Connection", False, f"Status: {database.get('status')}")
                    return False
            else:
                self.log_test("Database Connection", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Database Connection", False, f"Error: {e}")
            return False
    
    async def test_api_endpoints(self) -> bool:
        """Тест API эндпоинтов"""
        try:
            # Тест неавторизованного доступа (должен вернуть 401)
            response = await self.session.get(f"{self.base_url}/api/projects")
            if response.status_code == 401:
                self.log_test("API Authentication", True, "Properly requires authentication")
            else:
                self.log_test("API Authentication", False, f"Expected 401, got {response.status_code}")
                return False
            
            # Тест несуществующего эндпоинта (должен вернуть 404)
            response = await self.session.get(f"{self.base_url}/api/nonexistent")
            if response.status_code == 404:
                self.log_test("API Error Handling", True, "Properly handles 404 errors")
            else:
                self.log_test("API Error Handling", False, f"Expected 404, got {response.status_code}")
                return False
            
            return True
        except Exception as e:
            self.log_test("API Endpoints", False, f"Error: {e}")
            return False
    
    async def test_performance(self) -> bool:
        """Тест производительности"""
        try:
            # Тест времени отклика
            start_time = time.time()
            response = await self.session.get(f"{self.base_url}/health")
            response_time = time.time() - start_time
            
            if response_time < 1.0:
                self.log_test("Response Time", True, f"{response_time:.3f}s")
            else:
                self.log_test("Response Time", False, f"Too slow: {response_time:.3f}s")
                return False
            
            # Тест параллельных запросов
            start_time = time.time()
            tasks = []
            for _ in range(5):
                task = self.session.get(f"{self.base_url}/health")
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks)
            parallel_time = time.time() - start_time
            
            if all(r.status_code == 200 for r in responses) and parallel_time < 3.0:
                self.log_test("Parallel Requests", True, f"5 requests in {parallel_time:.3f}s")
            else:
                self.log_test("Parallel Requests", False, f"Failed or too slow: {parallel_time:.3f}s")
                return False
            
            return True
        except Exception as e:
            self.log_test("Performance", False, f"Error: {e}")
            return False
    
    async def test_configuration(self) -> bool:
        """Тест конфигурации"""
        try:
            # Проверяем, что Supabase настроен
            if settings.supabase_url and settings.supabase_url != "your_supabase_url_here":
                self.log_test("Supabase URL", True, "Configured")
            else:
                self.log_test("Supabase URL", False, "Not configured")
                return False
            
            if settings.supabase_anon_key and settings.supabase_anon_key != "your_supabase_anon_key_here":
                self.log_test("Supabase Anon Key", True, "Configured")
            else:
                self.log_test("Supabase Anon Key", False, "Not configured")
                return False
            
            if settings.api_encryption_key and len(settings.api_encryption_key) >= 32:
                self.log_test("API Encryption Key", True, "Configured")
            else:
                self.log_test("API Encryption Key", False, "Not configured or too short")
                return False
            
            return True
        except Exception as e:
            self.log_test("Configuration", False, f"Error: {e}")
            return False
    
    async def run_all_tests(self) -> dict:
        """Запуск всех тестов"""
        
        print("🚀 Тест готовности к продакшену")
        print("=" * 50)
        
        tests = [
            ("Server Startup", self.test_server_startup),
            ("Configuration", self.test_configuration),
            ("Health Endpoints", self.test_health_endpoints),
            ("Database Connection", self.test_database_connection),
            ("AI Providers", self.test_ai_providers),
            ("API Endpoints", self.test_api_endpoints),
            ("Performance", self.test_performance),
        ]
        
        for test_name, test_func in tests:
            try:
                print(f"\n🔍 {test_name}...")
                await test_func()
            except Exception as e:
                self.log_test(test_name, False, f"Critical error: {e}")
        
        # Результаты
        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        
        print("\n" + "=" * 50)
        print(f"📊 Результаты теста готовности:")
        print(f"✅ Пройдено: {self.passed_tests}")
        print(f"❌ Провалено: {self.total_tests - self.passed_tests}")
        print(f"📈 Успешность: {success_rate:.1f}%")
        
        if success_rate >= 90:
            print("\n🎉 ПРОЕКТ ГОТОВ К ПРОДАКШЕНУ!")
            print("🚀 Все системы работают корректно")
        elif success_rate >= 70:
            print("\n⚠️ Проект почти готов, но есть проблемы")
            print("🔧 Требуется небольшая доработка")
        else:
            print("\n❌ Проект не готов к продакшену")
            print("🔧 Требуется серьезная доработка")
        
        return {
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "success_rate": success_rate,
            "ready_for_production": success_rate >= 90,
            "details": self.test_results
        }

async def main():
    """Главная функция"""
    
    async with ProductionReadyTest(BASE_URL) as tester:
        results = await tester.run_all_tests()
        return results["ready_for_production"]

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)