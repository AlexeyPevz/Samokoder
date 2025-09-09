#!/usr/bin/env python3
"""
Comprehensive тест всех компонентов проекта Самокодер
Проверяет все системы на баги и готовность к продакшену
"""

import asyncio
import sys
import os
import json
import requests
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any

# Добавляем путь к проекту
sys.path.append(str(Path(__file__).parent))

class ComprehensiveTester:
    """Comprehensive тестер для всех компонентов проекта"""
    
    def __init__(self):
        self.results = {}
        self.base_url = "http://localhost:8000"
        self.server_process = None
        
    async def run_all_tests(self):
        """Запускает все тесты"""
        print("🧪 COMPREHENSIVE ТЕСТИРОВАНИЕ ПРОЕКТА САМОКОДЕР")
        print("=" * 60)
        
        # 1. Проверка структуры проекта
        await self.test_project_structure()
        
        # 2. Проверка зависимостей
        await self.test_dependencies()
        
        # 3. Проверка конфигурации
        await self.test_configuration()
        
        # 4. Проверка импортов
        await self.test_imports()
        
        # 5. Запуск сервера и тестирование API
        await self.test_api_endpoints()
        
        # 6. Тестирование GPT-Pilot интеграции
        await self.test_gpt_pilot_integration()
        
        # 7. Тестирование файловой системы
        await self.test_file_system()
        
        # 8. Тестирование безопасности
        await self.test_security()
        
        # 9. Генерация отчета
        await self.generate_report()
        
        return self.results
    
    async def test_project_structure(self):
        """Тестирует структуру проекта"""
        print("\n📁 Тестирование структуры проекта...")
        
        required_files = [
            "backend/main.py",
            "backend/services/gpt_pilot_wrapper_v2.py",
            "backend/services/gpt_pilot_simple_adapter.py",
            "backend/auth/dependencies.py",
            "config/settings.py",
            "requirements.txt",
            ".env",
            "database/schema.sql",
            "database/init_data.sql"
        ]
        
        required_dirs = [
            "backend",
            "backend/services",
            "backend/auth",
            "config",
            "database",
            "samokoder-core"
        ]
        
        missing_files = []
        missing_dirs = []
        
        for file_path in required_files:
            if not Path(file_path).exists():
                missing_files.append(file_path)
        
        for dir_path in required_dirs:
            if not Path(dir_path).exists():
                missing_dirs.append(dir_path)
        
        if missing_files or missing_dirs:
            print(f"❌ Отсутствуют файлы: {missing_files}")
            print(f"❌ Отсутствуют директории: {missing_dirs}")
            self.results['project_structure'] = False
        else:
            print("✅ Структура проекта корректна")
            self.results['project_structure'] = True
    
    async def test_dependencies(self):
        """Тестирует зависимости"""
        print("\n📦 Тестирование зависимостей...")
        
        try:
            # Проверяем requirements.txt на дубликаты
            with open("requirements.txt", "r") as f:
                lines = f.readlines()
            
            packages = []
            duplicates = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    package = line.split("==")[0].split(">=")[0].split("<=")[0]
                    if package in packages:
                        duplicates.append(package)
                    packages.append(package)
            
            if duplicates:
                print(f"❌ Найдены дубликаты зависимостей: {duplicates}")
                self.results['dependencies'] = False
            else:
                print("✅ Зависимости корректны")
                self.results['dependencies'] = True
                
        except Exception as e:
            print(f"❌ Ошибка проверки зависимостей: {e}")
            self.results['dependencies'] = False
    
    async def test_configuration(self):
        """Тестирует конфигурацию"""
        print("\n⚙️ Тестирование конфигурации...")
        
        try:
            # Проверяем .env файл
            with open(".env", "r") as f:
                env_content = f.read()
            
            required_vars = [
                "SUPABASE_URL",
                "SUPABASE_ANON_KEY",
                "SUPABASE_SERVICE_ROLE_KEY",
                "API_ENCRYPTION_KEY",
                "CORS_ORIGINS"
            ]
            
            missing_vars = []
            for var in required_vars:
                if f"{var}=" not in env_content:
                    missing_vars.append(var)
            
            # Проверяем формат CORS_ORIGINS
            cors_format_ok = 'CORS_ORIGINS=["' in env_content
            
            if missing_vars or not cors_format_ok:
                print(f"❌ Отсутствуют переменные: {missing_vars}")
                if not cors_format_ok:
                    print("❌ Неправильный формат CORS_ORIGINS")
                self.results['configuration'] = False
            else:
                print("✅ Конфигурация корректна")
                self.results['configuration'] = True
                
        except Exception as e:
            print(f"❌ Ошибка проверки конфигурации: {e}")
            self.results['configuration'] = False
    
    async def test_imports(self):
        """Тестирует импорты"""
        print("\n📥 Тестирование импортов...")
        
        test_files = [
            "backend/main.py",
            "backend/services/gpt_pilot_wrapper_v2.py",
            "backend/services/gpt_pilot_simple_adapter.py",
            "backend/auth/dependencies.py",
            "config/settings.py"
        ]
        
        import_errors = []
        
        for file_path in test_files:
            try:
                # Попытка импорта модуля
                if file_path == "backend/main.py":
                    # Специальная обработка для main.py
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("main", file_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                else:
                    # Для остальных файлов
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("test_module", file_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
            except Exception as e:
                import_errors.append(f"{file_path}: {str(e)}")
        
        if import_errors:
            print(f"❌ Ошибки импорта: {import_errors}")
            self.results['imports'] = False
        else:
            print("✅ Импорты корректны")
            self.results['imports'] = True
    
    async def test_api_endpoints(self):
        """Тестирует API эндпойнты"""
        print("\n🌐 Тестирование API эндпойнтов...")
        
        try:
            # Запускаем сервер
            await self.start_server()
            
            # Ждем запуска сервера
            await asyncio.sleep(3)
            
            # Тестируем эндпойнты
            endpoints = [
                ("/", "GET"),
                ("/health", "GET"),
                ("/api/info", "GET"),
                ("/docs", "GET")
            ]
            
            endpoint_results = []
            
            for endpoint, method in endpoints:
                try:
                    if method == "GET":
                        response = requests.get(f"{self.base_url}{endpoint}", timeout=5)
                        if response.status_code == 200:
                            endpoint_results.append(True)
                        else:
                            endpoint_results.append(False)
                except Exception as e:
                    endpoint_results.append(False)
            
            if all(endpoint_results):
                print("✅ API эндпойнты работают")
                self.results['api_endpoints'] = True
            else:
                print("❌ Некоторые API эндпойнты не работают")
                self.results['api_endpoints'] = False
                
        except Exception as e:
            print(f"❌ Ошибка тестирования API: {e}")
            self.results['api_endpoints'] = False
        finally:
            await self.stop_server()
    
    async def test_gpt_pilot_integration(self):
        """Тестирует интеграцию с GPT-Pilot"""
        print("\n🤖 Тестирование интеграции с GPT-Pilot...")
        
        try:
            # Импортируем и тестируем компоненты
            from backend.services.gpt_pilot_simple_adapter import SamokoderGPTPilotSimpleAdapter
            from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot
            
            # Тестовые данные
            project_id = "test_comprehensive"
            user_id = "test_user"
            user_api_keys = {"openai": "sk-test-key"}
            
            # Тестируем адаптер
            adapter = SamokoderGPTPilotSimpleAdapter(project_id, user_id, user_api_keys)
            result = await adapter.initialize_project("Test App", "Test Description")
            
            if result['status'] == 'initialized':
                print("✅ GPT-Pilot адаптер работает")
                adapter_ok = True
            else:
                print("❌ GPT-Pilot адаптер не работает")
                adapter_ok = False
            
            # Тестируем wrapper
            wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
            result = await wrapper.initialize_project("Test App", "Test Description")
            
            if result['status'] == 'initialized':
                print("✅ GPT-Pilot wrapper работает")
                wrapper_ok = True
            else:
                print("❌ GPT-Pilot wrapper не работает")
                wrapper_ok = False
            
            self.results['gpt_pilot_integration'] = adapter_ok and wrapper_ok
            
        except Exception as e:
            print(f"❌ Ошибка тестирования GPT-Pilot: {e}")
            self.results['gpt_pilot_integration'] = False
    
    async def test_file_system(self):
        """Тестирует файловую систему"""
        print("\n💾 Тестирование файловой системы...")
        
        try:
            # Проверяем создание директорий
            test_dirs = ["exports", "workspaces", "workspaces/test_user"]
            
            for dir_path in test_dirs:
                Path(dir_path).mkdir(parents=True, exist_ok=True)
            
            # Проверяем создание файлов
            test_file = Path("workspaces/test_user/test_file.txt")
            test_file.write_text("test content")
            
            # Проверяем чтение файлов
            content = test_file.read_text()
            
            # Очищаем тестовые файлы
            test_file.unlink()
            
            if content == "test content":
                print("✅ Файловая система работает")
                self.results['file_system'] = True
            else:
                print("❌ Файловая система не работает")
                self.results['file_system'] = False
                
        except Exception as e:
            print(f"❌ Ошибка тестирования файловой системы: {e}")
            self.results['file_system'] = False
    
    async def test_security(self):
        """Тестирует безопасность"""
        print("\n🔒 Тестирование безопасности...")
        
        try:
            # Проверяем наличие файлов безопасности
            security_files = [
                "backend/services/encryption.py",
                "backend/auth/dependencies.py"
            ]
            
            security_ok = True
            
            for file_path in security_files:
                if not Path(file_path).exists():
                    print(f"❌ Отсутствует файл безопасности: {file_path}")
                    security_ok = False
            
            # Проверяем настройки безопасности в .env
            with open(".env", "r") as f:
                env_content = f.read()
            
            if "your-secret-key-here" in env_content:
                print("⚠️ Используются placeholder ключи безопасности")
                security_ok = False
            
            if security_ok:
                print("✅ Безопасность настроена")
                self.results['security'] = True
            else:
                print("❌ Проблемы с безопасностью")
                self.results['security'] = False
                
        except Exception as e:
            print(f"❌ Ошибка тестирования безопасности: {e}")
            self.results['security'] = False
    
    async def start_server(self):
        """Запускает тестовый сервер"""
        try:
            cmd = ["bash", "-c", "source venv/bin/activate && python test_server.py"]
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except Exception as e:
            print(f"Ошибка запуска сервера: {e}")
    
    async def stop_server(self):
        """Останавливает сервер"""
        if self.server_process:
            self.server_process.terminate()
            self.server_process.wait()
    
    async def generate_report(self):
        """Генерирует отчет о тестировании"""
        print("\n📊 ГЕНЕРАЦИЯ ОТЧЕТА...")
        print("=" * 40)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for result in self.results.values() if result)
        
        print(f"Всего тестов: {total_tests}")
        print(f"Пройдено: {passed_tests}")
        print(f"Провалено: {total_tests - passed_tests}")
        print(f"Процент успеха: {(passed_tests/total_tests)*100:.1f}%")
        
        print("\nДетальные результаты:")
        for test_name, result in self.results.items():
            status = "✅" if result else "❌"
            print(f"  {status} {test_name}")
        
        # Определяем общий статус
        if passed_tests == total_tests:
            print("\n🎉 ВСЕ ТЕСТЫ ПРОШЛИ УСПЕШНО!")
            print("✅ Проект готов к продакшену!")
        elif passed_tests >= total_tests * 0.8:
            print("\n⚠️ БОЛЬШИНСТВО ТЕСТОВ ПРОШЛО")
            print("🔧 Требуются незначительные исправления")
        else:
            print("\n❌ МНОГО ТЕСТОВ НЕ ПРОШЛО")
            print("🚨 Требуются серьезные исправления")

async def main():
    """Основная функция"""
    tester = ComprehensiveTester()
    await tester.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main())