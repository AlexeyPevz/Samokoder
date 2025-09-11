#!/usr/bin/env python3
"""
Security Fixes Test Script
Тестирование примененных исправлений безопасности
"""

import sys
import os
import json
from pathlib import Path

def test_file_exists(file_path: str) -> bool:
    """Проверяет существование файла"""
    return Path(file_path).exists()

def test_file_content(file_path: str, required_strings: list) -> bool:
    """Проверяет содержимое файла на наличие обязательных строк"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        for required_string in required_strings:
            if required_string not in content:
                print(f"❌ Не найдено: {required_string} в {file_path}")
                return False
        
        return True
    except Exception as e:
        print(f"❌ Ошибка чтения файла {file_path}: {e}")
        return False

def test_security_fixes():
    """Тестирует примененные исправления безопасности"""
    
    print("🔍 Тестирование исправлений безопасности...")
    print("=" * 50)
    
    tests_passed = 0
    total_tests = 0
    
    # Тест 1: Проверка существования исправленных файлов
    print("\n1. Проверка существования исправленных файлов:")
    
    files_to_check = [
        "backend/auth/dependencies.py",
        "backend/api/auth.py", 
        "backend/validators/secure_input_validator.py",
        "backend/middleware/secure_rate_limiter.py",
        "backend/middleware/secure_error_handler.py",
        "tests/test_security.py",
        "requirements-security.txt"
    ]
    
    for file_path in files_to_check:
        total_tests += 1
        if test_file_exists(file_path):
            print(f"✅ {file_path}")
            tests_passed += 1
        else:
            print(f"❌ {file_path}")
    
    # Тест 2: Проверка содержимого auth/dependencies.py
    print("\n2. Проверка содержимого auth/dependencies.py:")
    
    required_auth_deps = [
        "validate_jwt_token",
        "secure_password_validation", 
        "hash_password",
        "verify_password",
        "jwt",
        "time",
        "hashlib"
    ]
    
    total_tests += 1
    if test_file_content("backend/auth/dependencies.py", required_auth_deps):
        print("✅ auth/dependencies.py содержит все необходимые исправления")
        tests_passed += 1
    else:
        print("❌ auth/dependencies.py не содержит все необходимые исправления")
    
    # Тест 3: Проверка содержимого api/auth.py
    print("\n3. Проверка содержимого api/auth.py:")
    
    required_auth_api = [
        "STRICT_RATE_LIMITS",
        "check_rate_limit",
        "secure_password_validation",
        "hash_password",
        "client_ip",
        "Too many login attempts"
    ]
    
    total_tests += 1
    if test_file_content("backend/api/auth.py", required_auth_api):
        print("✅ api/auth.py содержит все необходимые исправления")
        tests_passed += 1
    else:
        print("❌ api/auth.py не содержит все необходимые исправления")
    
    # Тест 4: Проверка содержимого main.py
    print("\n4. Проверка содержимого main.py:")
    
    required_main = [
        "allowed_origins",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "X-CSRF-Token",
        "csrf_protect"
    ]
    
    total_tests += 1
    if test_file_content("backend/main.py", required_main):
        print("✅ main.py содержит все необходимые исправления")
        tests_passed += 1
    else:
        print("❌ main.py не содержит все необходимые исправления")
    
    # Тест 5: Проверка secure_input_validator.py
    print("\n5. Проверка secure_input_validator.py:")
    
    required_validator = [
        "SQL_INJECTION_PATTERNS",
        "XSS_PATTERNS", 
        "PATH_TRAVERSAL_PATTERNS",
        "bleach",
        "validate_and_sanitize_string",
        "validate_json_data"
    ]
    
    total_tests += 1
    if test_file_content("backend/validators/secure_input_validator.py", required_validator):
        print("✅ secure_input_validator.py содержит все необходимые исправления")
        tests_passed += 1
    else:
        print("❌ secure_input_validator.py не содержит все необходимые исправления")
    
    # Тест 6: Проверка secure_rate_limiter.py
    print("\n6. Проверка secure_rate_limiter.py:")
    
    required_rate_limiter = [
        "SecureRateLimiter",
        "auth_limits",
        "general_limits",
        "check_rate_limit",
        "rate_limit_exceeded"
    ]
    
    total_tests += 1
    if test_file_content("backend/middleware/secure_rate_limiter.py", required_rate_limiter):
        print("✅ secure_rate_limiter.py содержит все необходимые исправления")
        tests_passed += 1
    else:
        print("❌ secure_rate_limiter.py не содержит все необходимые исправления")
    
    # Тест 7: Проверка secure_error_handler.py
    print("\n7. Проверка secure_error_handler.py:")
    
    required_error_handler = [
        "SecureErrorResponse",
        "sanitize_error_message",
        "secure_validation_exception_handler",
        "secure_http_exception_handler",
        "secure_general_exception_handler"
    ]
    
    total_tests += 1
    if test_file_content("backend/middleware/secure_error_handler.py", required_error_handler):
        print("✅ secure_error_handler.py содержит все необходимые исправления")
        tests_passed += 1
    else:
        print("❌ secure_error_handler.py не содержит все необходимые исправления")
    
    # Тест 8: Проверка requirements-security.txt
    print("\n8. Проверка requirements-security.txt:")
    
    required_packages = [
        "PyJWT",
        "cryptography",
        "fastapi-csrf-protect",
        "slowapi",
        "redis",
        "bleach",
        "bcrypt",
        "argon2-cffi"
    ]
    
    total_tests += 1
    if test_file_content("requirements-security.txt", required_packages):
        print("✅ requirements-security.txt содержит все необходимые пакеты")
        tests_passed += 1
    else:
        print("❌ requirements-security.txt не содержит все необходимые пакеты")
    
    # Тест 9: Проверка тестов безопасности
    print("\n9. Проверка тестов безопасности:")
    
    required_tests = [
        "TestAuthenticationSecurity",
        "TestInputValidation",
        "TestCORSecurity",
        "test_invalid_jwt_token_rejected",
        "test_sql_injection_prevention",
        "test_xss_prevention"
    ]
    
    total_tests += 1
    if test_file_content("tests/test_security.py", required_tests):
        print("✅ test_security.py содержит все необходимые тесты")
        tests_passed += 1
    else:
        print("❌ test_security.py не содержит все необходимые тесты")
    
    # Итоговый результат
    print("\n" + "=" * 50)
    print(f"📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:")
    print(f"✅ Пройдено: {tests_passed}/{total_tests}")
    print(f"❌ Провалено: {total_tests - tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ! Исправления безопасности применены успешно.")
        print("\n📋 СЛЕДУЮЩИЕ ШАГИ:")
        print("1. Установите зависимости: pip install -r requirements-security.txt")
        print("2. Запустите тесты: pytest tests/test_security.py")
        print("3. Перезапустите приложение для применения изменений")
        print("4. Проведите дополнительное тестирование в staging окружении")
        return True
    else:
        print(f"\n⚠️  НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ. Проверьте файлы и повторите исправления.")
        return False

def main():
    """Основная функция"""
    print("🔒 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЙ БЕЗОПАСНОСТИ SAMOKODER")
    print("=" * 60)
    
    success = test_security_fixes()
    
    if success:
        print("\n✅ Все исправления безопасности успешно применены!")
        sys.exit(0)
    else:
        print("\n❌ Обнаружены проблемы с исправлениями безопасности!")
        sys.exit(1)

if __name__ == "__main__":
    main()