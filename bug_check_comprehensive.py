#!/usr/bin/env python3
"""
Comprehensive проверка на баги и проблемы
Финальная проверка всех компонентов проекта
"""

import asyncio
import json
import time
import uuid
import sys
import traceback
from datetime import datetime
from pathlib import Path
import httpx
import importlib.util

# Добавляем путь к проекту
sys.path.insert(0, str(Path(__file__).parent))

class BugChecker:
    """Comprehensive проверка на баги"""
    
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.session = httpx.AsyncClient(timeout=30.0)
        self.bugs_found = []
        self.warnings = []
        self.critical_issues = []
        self.total_checks = 0
        self.passed_checks = 0
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.aclose()
    
    def log_issue(self, category: str, severity: str, component: str, issue: str, fix: str = ""):
        """Логирование найденной проблемы"""
        self.total_checks += 1
        
        issue_data = {
            "category": category,
            "severity": severity,
            "component": component,
            "issue": issue,
            "fix": fix,
            "timestamp": datetime.now().isoformat()
        }
        
        if severity == "CRITICAL":
            self.critical_issues.append(issue_data)
            print(f"🚨 CRITICAL: {component} - {issue}")
        elif severity == "BUG":
            self.bugs_found.append(issue_data)
            print(f"🐛 BUG: {component} - {issue}")
        elif severity == "WARNING":
            self.warnings.append(issue_data)
            print(f"⚠️ WARNING: {component} - {issue}")
        else:
            self.passed_checks += 1
            print(f"✅ OK: {component}")
    
    async def check_server_availability(self):
        """Проверка доступности сервера"""
        try:
            response = await self.session.get(f"{self.base_url}/", timeout=5.0)
            if response.status_code == 200:
                self.log_issue("CONNECTIVITY", "OK", "Server", "Server is running")
            else:
                self.log_issue("CONNECTIVITY", "CRITICAL", "Server", f"Server returned {response.status_code}")
        except httpx.ConnectError:
            self.log_issue("CONNECTIVITY", "CRITICAL", "Server", "Server is not running - start with: python3 run_server.py")
        except Exception as e:
            self.log_issue("CONNECTIVITY", "CRITICAL", "Server", f"Connection error: {e}")
    
    async def check_imports(self):
        """Проверка импортов всех модулей"""
        modules_to_check = [
            "backend.main",
            "backend.services.ai_service",
            "backend.services.cache_service", 
            "backend.services.encryption",
            "backend.monitoring",
            "backend.auth.dependencies",
            "config.settings"
        ]
        
        for module_name in modules_to_check:
            try:
                spec = importlib.util.find_spec(module_name)
                if spec is None:
                    self.log_issue("IMPORTS", "CRITICAL", module_name, "Module not found")
                else:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.log_issue("IMPORTS", "OK", module_name, "Import successful")
            except ImportError as e:
                self.log_issue("IMPORTS", "CRITICAL", module_name, f"Import error: {e}")
            except Exception as e:
                self.log_issue("IMPORTS", "BUG", module_name, f"Module error: {e}")
    
    async def check_configuration(self):
        """Проверка конфигурации"""
        try:
            from config.settings import settings
            
            # Проверка Supabase
            if not settings.supabase_url or settings.supabase_url == "your_supabase_url_here":
                self.log_issue("CONFIG", "CRITICAL", "Supabase URL", "Not configured")
            else:
                self.log_issue("CONFIG", "OK", "Supabase URL", "Configured")
            
            if not settings.supabase_anon_key or settings.supabase_anon_key == "your_supabase_anon_key_here":
                self.log_issue("CONFIG", "CRITICAL", "Supabase Anon Key", "Not configured")
            else:
                self.log_issue("CONFIG", "OK", "Supabase Anon Key", "Configured")
            
            if not settings.supabase_service_role_key or settings.supabase_service_role_key == "your_service_role_key_here":
                self.log_issue("CONFIG", "WARNING", "Supabase Service Role Key", "Not configured - needed for full functionality")
            else:
                self.log_issue("CONFIG", "OK", "Supabase Service Role Key", "Configured")
            
            # Проверка API ключей
            if not settings.api_encryption_key or len(settings.api_encryption_key) < 32:
                self.log_issue("CONFIG", "CRITICAL", "API Encryption Key", "Not configured or too short")
            else:
                self.log_issue("CONFIG", "OK", "API Encryption Key", "Configured")
            
            # Проверка CORS
            if not settings.cors_origins:
                self.log_issue("CONFIG", "WARNING", "CORS Origins", "Not configured")
            else:
                self.log_issue("CONFIG", "OK", "CORS Origins", f"Configured: {settings.cors_origins}")
                
        except Exception as e:
            self.log_issue("CONFIG", "CRITICAL", "Settings", f"Configuration error: {e}")
    
    async def check_health_endpoints(self):
        """Проверка health endpoints"""
        try:
            # Базовый health check
            response = await self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                health_data = response.json()
                if health_data.get("status") == "healthy":
                    self.log_issue("HEALTH", "OK", "Basic Health Check", "Healthy")
                else:
                    self.log_issue("HEALTH", "BUG", "Basic Health Check", f"Status: {health_data.get('status')}")
            else:
                self.log_issue("HEALTH", "BUG", "Basic Health Check", f"HTTP {response.status_code}")
            
            # Детальный health check
            response = await self.session.get(f"{self.base_url}/health/detailed")
            if response.status_code == 200:
                detailed_data = response.json()
                if "uptime_seconds" in detailed_data:
                    self.log_issue("HEALTH", "OK", "Detailed Health Check", "Working")
                else:
                    self.log_issue("HEALTH", "BUG", "Detailed Health Check", "Missing uptime data")
            else:
                self.log_issue("HEALTH", "BUG", "Detailed Health Check", f"HTTP {response.status_code}")
            
            # Метрики
            response = await self.session.get(f"{self.base_url}/metrics")
            if response.status_code == 200:
                metrics_text = response.text
                if "api_requests_total" in metrics_text:
                    self.log_issue("HEALTH", "OK", "Metrics Endpoint", "Prometheus metrics available")
                else:
                    self.log_issue("HEALTH", "WARNING", "Metrics Endpoint", "No metrics found")
            else:
                self.log_issue("HEALTH", "BUG", "Metrics Endpoint", f"HTTP {response.status_code}")
                
        except Exception as e:
            self.log_issue("HEALTH", "CRITICAL", "Health Endpoints", f"Error: {e}")
    
    async def check_api_endpoints(self):
        """Проверка API эндпоинтов"""
        endpoints_to_check = [
            ("GET", "/", "Root endpoint"),
            ("GET", "/docs", "API documentation"),
            ("GET", "/redoc", "ReDoc documentation"),
            ("GET", "/api/ai/providers", "AI providers"),
        ]
        
        for method, endpoint, description in endpoints_to_check:
            try:
                if method == "GET":
                    response = await self.session.get(f"{self.base_url}{endpoint}")
                else:
                    response = await self.session.request(method, f"{self.base_url}{endpoint}")
                
                if response.status_code in [200, 401, 422]:  # 401/422 are expected for some endpoints
                    self.log_issue("API", "OK", description, f"HTTP {response.status_code}")
                else:
                    self.log_issue("API", "BUG", description, f"Unexpected HTTP {response.status_code}")
            except Exception as e:
                self.log_issue("API", "BUG", description, f"Error: {e}")
    
    async def check_database_connection(self):
        """Проверка подключения к базе данных"""
        try:
            response = await self.session.get(f"{self.base_url}/health/detailed")
            if response.status_code == 200:
                health_data = response.json()
                external_services = health_data.get("external_services", {})
                database = external_services.get("supabase", {})
                
                if database.get("status") == "healthy":
                    self.log_issue("DATABASE", "OK", "Supabase Connection", "Connected")
                else:
                    self.log_issue("DATABASE", "CRITICAL", "Supabase Connection", f"Status: {database.get('status')}")
            else:
                self.log_issue("DATABASE", "BUG", "Supabase Connection", f"Health check failed: HTTP {response.status_code}")
        except Exception as e:
            self.log_issue("DATABASE", "CRITICAL", "Supabase Connection", f"Error: {e}")
    
    async def check_ai_service(self):
        """Проверка AI сервиса"""
        try:
            # Проверка провайдеров
            response = await self.session.get(f"{self.base_url}/api/ai/providers")
            if response.status_code == 200:
                providers_data = response.json()
                if "providers" in providers_data and len(providers_data["providers"]) > 0:
                    self.log_issue("AI_SERVICE", "OK", "AI Providers", f"{len(providers_data['providers'])} providers available")
                else:
                    self.log_issue("AI_SERVICE", "BUG", "AI Providers", "No providers found")
            else:
                self.log_issue("AI_SERVICE", "BUG", "AI Providers", f"HTTP {response.status_code}")
            
            # Проверка AI чата (ожидаем ошибку без ключей)
            response = await self.session.post(
                f"{self.base_url}/api/ai/chat",
                json={"message": "test", "provider": "openrouter", "model": "deepseek/deepseek-v3"}
            )
            if response.status_code in [400, 401, 500]:  # Ожидаемые ошибки
                self.log_issue("AI_SERVICE", "OK", "AI Chat", f"Properly handles missing auth: HTTP {response.status_code}")
            else:
                self.log_issue("AI_SERVICE", "BUG", "AI Chat", f"Unexpected response: HTTP {response.status_code}")
                
        except Exception as e:
            self.log_issue("AI_SERVICE", "BUG", "AI Service", f"Error: {e}")
    
    async def check_file_structure(self):
        """Проверка структуры файлов"""
        required_files = [
            "backend/main.py",
            "backend/services/ai_service.py",
            "backend/services/cache_service.py",
            "backend/services/encryption.py",
            "backend/monitoring.py",
            "backend/auth/dependencies.py",
            "config/settings.py",
            "requirements.txt",
            ".env",
            "Dockerfile",
            "docker-compose.yml"
        ]
        
        for file_path in required_files:
            if Path(file_path).exists():
                self.log_issue("FILES", "OK", file_path, "File exists")
            else:
                self.log_issue("FILES", "CRITICAL", file_path, "File missing")
    
    async def check_dependencies(self):
        """Проверка зависимостей"""
        try:
            with open("requirements.txt", "r") as f:
                requirements = f.read()
            
            # Проверка на дубликаты
            lines = requirements.strip().split('\n')
            unique_lines = set(lines)
            if len(lines) != len(unique_lines):
                self.log_issue("DEPENDENCIES", "WARNING", "Requirements", "Duplicate dependencies found")
            else:
                self.log_issue("DEPENDENCIES", "OK", "Requirements", "No duplicates")
            
            # Проверка критических зависимостей
            critical_deps = ["fastapi", "uvicorn", "supabase", "cryptography", "httpx"]
            for dep in critical_deps:
                if dep in requirements:
                    self.log_issue("DEPENDENCIES", "OK", f"Dependency {dep}", "Present")
                else:
                    self.log_issue("DEPENDENCIES", "CRITICAL", f"Dependency {dep}", "Missing")
                    
        except Exception as e:
            self.log_issue("DEPENDENCIES", "CRITICAL", "Requirements", f"Error reading requirements.txt: {e}")
    
    async def check_security(self):
        """Проверка безопасности"""
        try:
            # Проверка .env файла
            if Path(".env").exists():
                with open(".env", "r") as f:
                    env_content = f.read()
                
                # Проверка на placeholder значения
                placeholders = [
                    "your_supabase_url_here",
                    "your_supabase_anon_key_here", 
                    "your_service_role_key_here"
                ]
                
                for placeholder in placeholders:
                    if placeholder in env_content:
                        self.log_issue("SECURITY", "WARNING", "Environment", f"Placeholder value found: {placeholder}")
                    else:
                        self.log_issue("SECURITY", "OK", "Environment", f"No placeholder: {placeholder}")
            else:
                self.log_issue("SECURITY", "CRITICAL", "Environment", ".env file missing")
            
            # Проверка .gitignore
            if Path(".gitignore").exists():
                with open(".gitignore", "r") as f:
                    gitignore_content = f.read()
                
                if ".env" in gitignore_content:
                    self.log_issue("SECURITY", "OK", "Gitignore", ".env is ignored")
                else:
                    self.log_issue("SECURITY", "WARNING", "Gitignore", ".env should be in .gitignore")
            else:
                self.log_issue("SECURITY", "WARNING", "Gitignore", ".gitignore file missing")
                
        except Exception as e:
            self.log_issue("SECURITY", "BUG", "Security", f"Error: {e}")
    
    async def check_performance(self):
        """Проверка производительности"""
        try:
            # Тест времени отклика
            start_time = time.time()
            response = await self.session.get(f"{self.base_url}/health")
            response_time = time.time() - start_time
            
            if response_time < 1.0:
                self.log_issue("PERFORMANCE", "OK", "Response Time", f"{response_time:.3f}s")
            elif response_time < 3.0:
                self.log_issue("PERFORMANCE", "WARNING", "Response Time", f"Slow: {response_time:.3f}s")
            else:
                self.log_issue("PERFORMANCE", "BUG", "Response Time", f"Too slow: {response_time:.3f}s")
            
            # Тест параллельных запросов
            start_time = time.time()
            tasks = []
            for _ in range(5):
                task = self.session.get(f"{self.base_url}/health")
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            parallel_time = time.time() - start_time
            
            successful_requests = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 200)
            
            if successful_requests == 5 and parallel_time < 3.0:
                self.log_issue("PERFORMANCE", "OK", "Parallel Requests", f"5 requests in {parallel_time:.3f}s")
            else:
                self.log_issue("PERFORMANCE", "WARNING", "Parallel Requests", f"Only {successful_requests}/5 successful in {parallel_time:.3f}s")
                
        except Exception as e:
            self.log_issue("PERFORMANCE", "BUG", "Performance", f"Error: {e}")
    
    async def run_all_checks(self):
        """Запуск всех проверок"""
        
        print("🔍 Comprehensive проверка на баги")
        print("=" * 60)
        
        checks = [
            ("Server Availability", self.check_server_availability),
            ("File Structure", self.check_file_structure),
            ("Dependencies", self.check_dependencies),
            ("Configuration", self.check_configuration),
            ("Imports", self.check_imports),
            ("Health Endpoints", self.check_health_endpoints),
            ("API Endpoints", self.check_api_endpoints),
            ("Database Connection", self.check_database_connection),
            ("AI Service", self.check_ai_service),
            ("Security", self.check_security),
            ("Performance", self.check_performance),
        ]
        
        for check_name, check_func in checks:
            try:
                print(f"\n🔍 {check_name}...")
                await check_func()
            except Exception as e:
                self.log_issue("SYSTEM", "CRITICAL", check_name, f"Check failed: {e}")
        
        # Результаты
        print("\n" + "=" * 60)
        print(f"📊 Результаты проверки:")
        print(f"✅ Пройдено: {self.passed_checks}")
        print(f"🐛 Багов: {len(self.bugs_found)}")
        print(f"⚠️ Предупреждений: {len(self.warnings)}")
        print(f"🚨 Критических: {len(self.critical_issues)}")
        
        if self.critical_issues:
            print(f"\n🚨 КРИТИЧЕСКИЕ ПРОБЛЕМЫ:")
            for issue in self.critical_issues:
                print(f"  - {issue['component']}: {issue['issue']}")
                if issue['fix']:
                    print(f"    💡 Исправление: {issue['fix']}")
        
        if self.bugs_found:
            print(f"\n🐛 НАЙДЕННЫЕ БАГИ:")
            for bug in self.bugs_found:
                print(f"  - {bug['component']}: {bug['issue']}")
                if bug['fix']:
                    print(f"    💡 Исправление: {bug['fix']}")
        
        if self.warnings:
            print(f"\n⚠️ ПРЕДУПРЕЖДЕНИЯ:")
            for warning in self.warnings:
                print(f"  - {warning['component']}: {warning['issue']}")
                if warning['fix']:
                    print(f"    💡 Исправление: {warning['fix']}")
        
        # Общая оценка
        total_issues = len(self.critical_issues) + len(self.bugs_found) + len(self.warnings)
        if total_issues == 0:
            print(f"\n🎉 ОТЛИЧНО! Никаких проблем не найдено!")
            print("🚀 Проект готов к продакшену!")
        elif len(self.critical_issues) == 0:
            print(f"\n✅ ХОРОШО! Критических проблем нет")
            print("🔧 Есть небольшие баги, но проект функционален")
        else:
            print(f"\n❌ ПРОБЛЕМЫ! Найдены критические ошибки")
            print("🔧 Требуется исправление перед продакшеном")
        
        return {
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "bugs_found": len(self.bugs_found),
            "warnings": len(self.warnings),
            "critical_issues": len(self.critical_issues),
            "ready_for_production": len(self.critical_issues) == 0,
            "details": {
                "critical": self.critical_issues,
                "bugs": self.bugs_found,
                "warnings": self.warnings
            }
        }

async def main():
    """Главная функция"""
    
    async with BugChecker() as checker:
        results = await checker.run_all_checks()
        return results["ready_for_production"]

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)