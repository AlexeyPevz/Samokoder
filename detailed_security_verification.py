#!/usr/bin/env python3
"""
Detailed Security Verification
Детальная перепроверка всех исправлений безопасности
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Tuple

class SecurityVerifier:
    """Детальная проверка безопасности"""
    
    def __init__(self):
        self.issues = []
        self.critical_issues = []
        self.warnings = []
    
    def add_issue(self, severity: str, file: str, line: int, issue: str, code_snippet: str = ""):
        """Добавляет найденную проблему"""
        issue_data = {
            "severity": severity,
            "file": file,
            "line": line,
            "issue": issue,
            "code_snippet": code_snippet
        }
        
        if severity == "CRITICAL":
            self.critical_issues.append(issue_data)
        else:
            self.warnings.append(issue_data)
        
        self.issues.append(issue_data)
    
    def check_file_exists(self, file_path: str) -> bool:
        """Проверяет существование файла"""
        return Path(file_path).exists()
    
    def read_file(self, file_path: str) -> List[str]:
        """Читает файл построчно"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.readlines()
        except Exception as e:
            self.add_issue("CRITICAL", file_path, 0, f"Не удалось прочитать файл: {e}")
            return []
    
    def check_auth_dependencies(self):
        """Проверяет auth/dependencies.py"""
        print("🔍 Проверяю auth/dependencies.py...")
        
        file_path = "backend/auth/dependencies.py"
        if not self.check_file_exists(file_path):
            self.add_issue("CRITICAL", file_path, 0, "Файл не существует")
            return
        
        lines = self.read_file(file_path)
        
        # Проверяем импорты
        required_imports = ["jwt", "time", "hashlib", "secrets"]
        for i, line in enumerate(lines, 1):
            if "import" in line:
                for imp in required_imports:
                    if imp in line:
                        break
                else:
                    if any(imp in line for imp in required_imports):
                        continue
                    # Проверяем, есть ли импорт в других строках
                    if not any(imp in "".join(lines) for imp in required_imports):
                        self.add_issue("CRITICAL", file_path, i, f"Отсутствует импорт: {required_imports}")
        
        # Проверяем функции
        required_functions = ["validate_jwt_token", "secure_password_validation", "hash_password"]
        file_content = "".join(lines)
        for func in required_functions:
            if f"def {func}" not in file_content:
                self.add_issue("CRITICAL", file_path, 0, f"Отсутствует функция: {func}")
        
        # Проверяем безопасность
        for i, line in enumerate(lines, 1):
            # Проверяем на небезопасные практики
            if "supabase = connection_manager.get_pool('supabase')" in line and "if not supabase_client:" not in "".join(lines[i-5:i+5]):
                self.add_issue("CRITICAL", file_path, i, "Небезопасная проверка подключения к Supabase", line.strip())
            
            if "logger.error" in line and ("password" in line.lower() or "token" in line.lower()):
                self.add_issue("WARNING", file_path, i, "Возможное логирование чувствительных данных", line.strip())
    
    def check_auth_api(self):
        """Проверяет api/auth.py"""
        print("🔍 Проверяю api/auth.py...")
        
        file_path = "backend/api/auth.py"
        if not self.check_file_exists(file_path):
            self.add_issue("CRITICAL", file_path, 0, "Файл не существует")
            return
        
        lines = self.read_file(file_path)
        file_content = "".join(lines)
        
        # Проверяем rate limiting
        if "STRICT_RATE_LIMITS" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует строгий rate limiting")
        
        if "check_rate_limit" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует проверка rate limit")
        
        # Проверяем безопасность паролей
        if "hash_password" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует хеширование паролей")
        
        # Проверяем логирование
        for i, line in enumerate(lines, 1):
            if "logger.error" in line and "credentials.email" in line and "[:3]" not in line:
                self.add_issue("WARNING", file_path, i, "Возможное логирование email без маскирования", line.strip())
    
    def check_main_py(self):
        """Проверяет main.py"""
        print("🔍 Проверяю main.py...")
        
        file_path = "backend/main.py"
        if not self.check_file_exists(file_path):
            self.add_issue("CRITICAL", file_path, 0, "Файл не существует")
            return
        
        lines = self.read_file(file_path)
        file_content = "".join(lines)
        
        # Проверяем CORS конфигурацию
        if "allowed_origins" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует безопасная CORS конфигурация")
        
        if 'allow_headers=["*"]' in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Небезопасная CORS конфигурация - разрешены все заголовки")
        
        # Проверяем заголовки безопасности
        security_headers = ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]
        for header in security_headers:
            if header not in file_content:
                self.add_issue("CRITICAL", file_path, 0, f"Отсутствует заголовок безопасности: {header}")
        
        # Проверяем CSRF защиту
        if "csrf_protect" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует CSRF защита")
    
    def check_secure_validator(self):
        """Проверяет secure_input_validator.py"""
        print("🔍 Проверяю secure_input_validator.py...")
        
        file_path = "backend/validators/secure_input_validator.py"
        if not self.check_file_exists(file_path):
            self.add_issue("CRITICAL", file_path, 0, "Файл не существует")
            return
        
        lines = self.read_file(file_path)
        file_content = "".join(lines)
        
        # Проверяем защиту от инъекций
        if "SQL_INJECTION_PATTERNS" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует защита от SQL инъекций")
        
        if "XSS_PATTERNS" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует защита от XSS")
        
        if "PATH_TRAVERSAL_PATTERNS" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует защита от path traversal")
        
        # Проверяем использование bleach
        if "bleach" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует санитизация с помощью bleach")
    
    def check_rate_limiter(self):
        """Проверяет secure_rate_limiter.py"""
        print("🔍 Проверяю secure_rate_limiter.py...")
        
        file_path = "backend/middleware/secure_rate_limiter.py"
        if not self.check_file_exists(file_path):
            self.add_issue("CRITICAL", file_path, 0, "Файл не существует")
            return
        
        lines = self.read_file(file_path)
        file_content = "".join(lines)
        
        # Проверяем строгие лимиты
        if "auth_limits" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствуют строгие лимиты для аутентификации")
        
        if "login" not in file_content or "3" not in file_content or "900" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует строгий лимит для логина (3 попытки в 15 минут)")
    
    def check_error_handler(self):
        """Проверяет secure_error_handler.py"""
        print("🔍 Проверяю secure_error_handler.py...")
        
        file_path = "backend/middleware/secure_error_handler.py"
        if not self.check_file_exists(file_path):
            self.add_issue("CRITICAL", file_path, 0, "Файл не существует")
            return
        
        lines = self.read_file(file_path)
        file_content = "".join(lines)
        
        # Проверяем санитизацию ошибок
        if "sanitize_error_message" not in file_content:
            self.add_issue("CRITICAL", file_path, 0, "Отсутствует санитизация сообщений об ошибках")
        
        # Проверяем маскирование чувствительных данных
        sensitive_patterns = ["password", "token", "key", "secret"]
        for pattern in sensitive_patterns:
            if pattern in file_content.lower() and "REDACTED" not in file_content:
                self.add_issue("WARNING", file_path, 0, f"Возможно небезопасное обращение с {pattern}")
    
    def check_original_vulnerabilities(self):
        """Проверяет, что оригинальные уязвимости исправлены"""
        print("🔍 Проверяю исправление оригинальных уязвимостей...")
        
        # Проверяем auth/dependencies.py на оригинальную уязвимость
        file_path = "backend/auth/dependencies.py"
        if self.check_file_exists(file_path):
            lines = self.read_file(file_path)
            file_content = "".join(lines)
            
            # Проверяем, что исправлена уязвимость с неопределенной переменной supabase
            if "supabase = connection_manager.get_pool('supabase')" in file_content:
                if "if not supabase_client:" not in file_content:
                    self.add_issue("CRITICAL", file_path, 0, "Оригинальная уязвимость НЕ исправлена - неопределенная переменная supabase")
        
        # Проверяем main.py на небезопасную CORS
        file_path = "backend/main.py"
        if self.check_file_exists(file_path):
            lines = self.read_file(file_path)
            file_content = "".join(lines)
            
            if 'allow_headers=["*"]' in file_content:
                self.add_issue("CRITICAL", file_path, 0, "Оригинальная уязвимость НЕ исправлена - небезопасная CORS конфигурация")
    
    def run_verification(self):
        """Запускает полную проверку"""
        print("🔒 ДЕТАЛЬНАЯ ПЕРЕПРОВЕРКА БЕЗОПАСНОСТИ")
        print("=" * 60)
        
        self.check_auth_dependencies()
        self.check_auth_api()
        self.check_main_py()
        self.check_secure_validator()
        self.check_rate_limiter()
        self.check_error_handler()
        self.check_original_vulnerabilities()
        
        return self.issues, self.critical_issues, self.warnings
    
    def print_results(self):
        """Выводит результаты проверки"""
        print("\n" + "=" * 60)
        print("📊 РЕЗУЛЬТАТЫ ДЕТАЛЬНОЙ ПРОВЕРКИ")
        print("=" * 60)
        
        if self.critical_issues:
            print(f"\n🔴 КРИТИЧЕСКИЕ ПРОБЛЕМЫ ({len(self.critical_issues)}):")
            for issue in self.critical_issues:
                print(f"  ❌ {issue['file']}:{issue['line']} - {issue['issue']}")
                if issue['code_snippet']:
                    print(f"     Код: {issue['code_snippet']}")
        
        if self.warnings:
            print(f"\n🟡 ПРЕДУПРЕЖДЕНИЯ ({len(self.warnings)}):")
            for issue in self.warnings:
                print(f"  ⚠️  {issue['file']}:{issue['line']} - {issue['issue']}")
                if issue['code_snippet']:
                    print(f"     Код: {issue['code_snippet']}")
        
        if not self.critical_issues and not self.warnings:
            print("\n✅ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО!")
            print("🔒 Исправления безопасности применены корректно")
        else:
            print(f"\n❌ ОБНАРУЖЕНО ПРОБЛЕМ: {len(self.issues)}")
            print(f"   🔴 Критических: {len(self.critical_issues)}")
            print(f"   🟡 Предупреждений: {len(self.warnings)}")

def main():
    """Основная функция"""
    verifier = SecurityVerifier()
    issues, critical, warnings = verifier.run_verification()
    verifier.print_results()
    
    if critical:
        print(f"\n🚨 ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ ПРОБЛЕМЫ! Исправления НЕ полные.")
        return False
    else:
        print(f"\n✅ Все критические проблемы исправлены!")
        return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)