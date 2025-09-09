#!/usr/bin/env python3
"""
Финальная comprehensive проверка проекта Самокодер
Проверяет все системы на баги, проблемы и готовность к продакшену
"""

import asyncio
import sys
import os
import json
import requests
import subprocess
import time
import importlib.util
from pathlib import Path
from typing import Dict, List, Any

# Добавляем путь к проекту
sys.path.append(str(Path(__file__).parent))

class FinalComprehensiveTester:
    """Финальный comprehensive тестер для всех компонентов проекта"""
    
    def __init__(self):
        self.results = {}
        self.base_url = "http://localhost:8000"
        self.server_process = None
        self.errors = []
        self.warnings = []
        
    async def run_all_tests(self):
        """Запускает все тесты"""
        print("🔍 ФИНАЛЬНАЯ COMPREHENSIVE ПРОВЕРКА ПРОЕКТА САМОКОДЕР")
        print("=" * 70)
        
        # 1. Проверка структуры проекта
        await self.test_project_structure()
        
        # 2. Проверка зависимостей
        await self.test_dependencies()
        
        # 3. Проверка конфигурации
        await self.test_configuration()
        
        # 4. Проверка импортов
        await self.test_imports()
        
        # 5. Проверка синтаксиса Python
        await self.test_python_syntax()
        
        # 6. Запуск сервера и тестирование API
        await self.test_api_endpoints()
        
        # 7. Тестирование GPT-Pilot интеграции
        await self.test_gpt_pilot_integration()
        
        # 8. Тестирование файловой системы
        await self.test_file_system()
        
        # 9. Тестирование безопасности
        await self.test_security()
        
        # 10. Проверка производительности
        await self.test_performance()
        
        # 11. Генерация отчета
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
            self.errors.extend(missing_files + missing_dirs)
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
            
            # Проверяем совместимость версий
            version_conflicts = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    if ">=" in line and "<=" in line:
                        # Проверяем, что минимальная версия меньше максимальной
                        parts = line.split(">=")[1].split("<=")
                        if len(parts) == 2:
                            min_ver = parts[0].strip()
                            max_ver = parts[1].strip()
                            if min_ver >= max_ver:
                                version_conflicts.append(line)
            
            if duplicates or version_conflicts:
                print(f"❌ Найдены дубликаты зависимостей: {duplicates}")
                print(f"❌ Конфликты версий: {version_conflicts}")
                self.results['dependencies'] = False
                self.errors.extend(duplicates + version_conflicts)
            else:
                print("✅ Зависимости корректны")
                self.results['dependencies'] = True
                
        except Exception as e:
            print(f"❌ Ошибка проверки зависимостей: {e}")
            self.results['dependencies'] = False
            self.errors.append(f"Dependencies error: {e}")
    
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
            placeholder_vars = []
            
            for var in required_vars:
                if f"{var}=" not in env_content:
                    missing_vars.append(var)
                elif f"{var}=your_" in env_content or f"{var}=your-" in env_content:
                    placeholder_vars.append(var)
            
            # Проверяем формат CORS_ORIGINS
            cors_format_ok = 'CORS_ORIGINS=["' in env_content
            
            # Проверяем длину ключей
            key_length_issues = []
            if "API_ENCRYPTION_KEY=" in env_content:
                key_line = [line for line in env_content.split('\n') if line.startswith('API_ENCRYPTION_KEY=')][0]
                key_value = key_line.split('=')[1]
                if len(key_value) < 32:
                    key_length_issues.append("API_ENCRYPTION_KEY too short")
            
            if missing_vars or placeholder_vars or not cors_format_ok or key_length_issues:
                print(f"❌ Отсутствуют переменные: {missing_vars}")
                print(f"⚠️ Placeholder переменные: {placeholder_vars}")
                if not cors_format_ok:
                    print("❌ Неправильный формат CORS_ORIGINS")
                if key_length_issues:
                    print(f"❌ Проблемы с ключами: {key_length_issues}")
                self.results['configuration'] = False
                self.errors.extend(missing_vars + placeholder_vars + key_length_issues)
            else:
                print("✅ Конфигурация корректна")
                self.results['configuration'] = True
                
        except Exception as e:
            print(f"❌ Ошибка проверки конфигурации: {e}")
            self.results['configuration'] = False
            self.errors.append(f"Configuration error: {e}")
    
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
                spec = importlib.util.spec_from_file_location("test_module", file_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
            except Exception as e:
                import_errors.append(f"{file_path}: {str(e)}")
        
        if import_errors:
            print(f"❌ Ошибки импорта: {import_errors}")
            self.results['imports'] = False
            self.errors.extend(import_errors)
        else:
            print("✅ Импорты корректны")
            self.results['imports'] = True
    
    async def test_python_syntax(self):
        """Тестирует синтаксис Python"""
        print("\n🐍 Тестирование синтаксиса Python...")
        
        python_files = [
            "backend/main.py",
            "backend/services/gpt_pilot_wrapper_v2.py",
            "backend/services/gpt_pilot_simple_adapter.py",
            "backend/auth/dependencies.py",
            "config/settings.py"
        ]
        
        syntax_errors = []
        
        for file_path in python_files:
            try:
                with open(file_path, 'r') as f:
                    compile(f.read(), file_path, 'exec')
            except SyntaxError as e:
                syntax_errors.append(f"{file_path}: {e}")
            except Exception as e:
                syntax_errors.append(f"{file_path}: {e}")
        
        if syntax_errors:
            print(f"❌ Ошибки синтаксиса: {syntax_errors}")
            self.results['python_syntax'] = False
            self.errors.extend(syntax_errors)
        else:
            print("✅ Синтаксис Python корректен")
            self.results['python_syntax'] = True
    
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
                            self.warnings.append(f"Endpoint {endpoint} returned {response.status_code}")
                except Exception as e:
                    endpoint_results.append(False)
                    self.errors.append(f"Endpoint {endpoint} error: {e}")
            
            if all(endpoint_results):
                print("✅ API эндпойнты работают")
                self.results['api_endpoints'] = True
            else:
                print("❌ Некоторые API эндпойнты не работают")
                self.results['api_endpoints'] = False
                
        except Exception as e:
            print(f"❌ Ошибка тестирования API: {e}")
            self.results['api_endpoints'] = False
            self.errors.append(f"API test error: {e}")
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
            project_id = "test_final_comprehensive"
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
                self.errors.append(f"GPT-Pilot adapter error: {result}")
            
            # Тестируем wrapper
            wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
            result = await wrapper.initialize_project("Test App", "Test Description")
            
            if result['status'] == 'initialized':
                print("✅ GPT-Pilot wrapper работает")
                wrapper_ok = True
            else:
                print("❌ GPT-Pilot wrapper не работает")
                wrapper_ok = False
                self.errors.append(f"GPT-Pilot wrapper error: {result}")
            
            self.results['gpt_pilot_integration'] = adapter_ok and wrapper_ok
            
        except Exception as e:
            print(f"❌ Ошибка тестирования GPT-Pilot: {e}")
            self.results['gpt_pilot_integration'] = False
            self.errors.append(f"GPT-Pilot integration error: {e}")
    
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
            test_content = "test content for comprehensive testing"
            test_file.write_text(test_content)
            
            # Проверяем чтение файлов
            read_content = test_file.read_text()
            
            # Проверяем права доступа
            file_permissions = oct(test_file.stat().st_mode)[-3:]
            
            # Очищаем тестовые файлы
            test_file.unlink()
            
            if read_content == test_content and file_permissions:
                print("✅ Файловая система работает")
                self.results['file_system'] = True
            else:
                print("❌ Файловая система не работает")
                self.results['file_system'] = False
                self.errors.append("File system test failed")
                
        except Exception as e:
            print(f"❌ Ошибка тестирования файловой системы: {e}")
            self.results['file_system'] = False
            self.errors.append(f"File system error: {e}")
    
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
                    self.errors.append(f"Missing security file: {file_path}")
            
            # Проверяем настройки безопасности в .env
            with open(".env", "r") as f:
                env_content = f.read()
            
            security_issues = []
            
            if "your-secret-key-here" in env_content:
                security_issues.append("Placeholder SECRET_KEY")
            
            if "your_supabase_url_here" in env_content:
                security_issues.append("Placeholder Supabase URL")
            
            if "your_32_character_encryption_key_here" in env_content:
                security_issues.append("Placeholder encryption key")
            
            if security_issues:
                print(f"⚠️ Проблемы безопасности: {security_issues}")
                self.warnings.extend(security_issues)
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
            self.errors.append(f"Security error: {e}")
    
    async def test_performance(self):
        """Тестирует производительность"""
        print("\n⚡ Тестирование производительности...")
        
        try:
            # Тестируем время инициализации компонентов
            start_time = time.time()
            
            from backend.services.gpt_pilot_simple_adapter import SamokoderGPTPilotSimpleAdapter
            adapter = SamokoderGPTPilotSimpleAdapter("perf_test", "test_user", {"openai": "sk-test"})
            
            init_time = time.time() - start_time
            
            if init_time < 1.0:  # Должно инициализироваться менее чем за секунду
                print("✅ Производительность инициализации хорошая")
                self.results['performance'] = True
            else:
                print(f"⚠️ Медленная инициализация: {init_time:.2f}s")
                self.warnings.append(f"Slow initialization: {init_time:.2f}s")
                self.results['performance'] = False
                
        except Exception as e:
            print(f"❌ Ошибка тестирования производительности: {e}")
            self.results['performance'] = False
            self.errors.append(f"Performance error: {e}")
    
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
        print("\n📊 ГЕНЕРАЦИЯ ФИНАЛЬНОГО ОТЧЕТА...")
        print("=" * 50)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for result in self.results.values() if result)
        
        print(f"Всего тестов: {total_tests}")
        print(f"Пройдено: {passed_tests}")
        print(f"Провалено: {total_tests - passed_tests}")
        print(f"Процент успеха: {(passed_tests/total_tests)*100:.1f}%")
        
        print(f"\nОшибки: {len(self.errors)}")
        print(f"Предупреждения: {len(self.warnings)}")
        
        print("\nДетальные результаты:")
        for test_name, result in self.results.items():
            status = "✅" if result else "❌"
            print(f"  {status} {test_name}")
        
        if self.errors:
            print("\n❌ Ошибки:")
            for error in self.errors[:10]:  # Показываем первые 10 ошибок
                print(f"  - {error}")
            if len(self.errors) > 10:
                print(f"  ... и еще {len(self.errors) - 10} ошибок")
        
        if self.warnings:
            print("\n⚠️ Предупреждения:")
            for warning in self.warnings[:10]:  # Показываем первые 10 предупреждений
                print(f"  - {warning}")
            if len(self.warnings) > 10:
                print(f"  ... и еще {len(self.warnings) - 10} предупреждений")
        
        # Определяем общий статус
        if passed_tests == total_tests and len(self.errors) == 0:
            print("\n🎉 ВСЕ ТЕСТЫ ПРОШЛИ УСПЕШНО!")
            print("✅ Проект готов к продакшену!")
        elif passed_tests >= total_tests * 0.8 and len(self.errors) <= 2:
            print("\n⚠️ БОЛЬШИНСТВО ТЕСТОВ ПРОШЛО")
            print("🔧 Требуются незначительные исправления")
        else:
            print("\n❌ МНОГО ТЕСТОВ НЕ ПРОШЛО")
            print("🚨 Требуются серьезные исправления")

async def main():
    """Основная функция"""
    tester = FinalComprehensiveTester()
    await tester.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main())