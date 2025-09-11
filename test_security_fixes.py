#!/usr/bin/env python3
"""
Тестирование исправлений безопасности - рефакторированная версия
"""

import os
import sys

def test_file_exists(file_path):
    """Проверяет существование файла"""
    try:
        return os.path.exists(file_path)
    except Exception as e:
        print(f"❌ Ошибка проверки файла {file_path}: {e}")
        return False

def test_file_content(file_path, required_content):
    """Проверяет содержимое файла"""
    try:
        if not os.path.exists(file_path):
            return False
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        for item in required_content:
            if item not in content:
                return False
        
        return True
    except Exception as e:
        print(f"❌ Ошибка чтения файла {file_path}: {e}")
        return False

def _test_file_existence():
    """Тест существования исправленных файлов"""
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
    
    tests_passed = 0
    total_tests = len(files_to_check)
    
    for file_path in files_to_check:
        if test_file_exists(file_path):
            print(f"✅ {file_path}")
            tests_passed += 1
        else:
            print(f"❌ {file_path}")
    
    return tests_passed, total_tests

def _test_import_functionality():
    """Тест функциональности импортов"""
    print("\n2. Проверка функциональности импортов:")
    
    tests_passed = 0
    total_tests = 0
    
    # Тест импорта auth dependencies
    total_tests += 1
    try:
        from backend.auth.dependencies import validate_jwt_token, secure_password_validation
        print("✅ backend.auth.dependencies")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ backend.auth.dependencies: {e}")
    
    # Тест импорта secure input validator
    total_tests += 1
    try:
        from backend.validators.secure_input_validator import SecureInputValidator
        print("✅ backend.validators.secure_input_validator")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ backend.validators.secure_input_validator: {e}")
    
    return tests_passed, total_tests

def test_security_fixes():
    """Тестирует примененные исправления безопасности"""
    
    print("🔍 Тестирование исправлений безопасности...")
    print("=" * 50)
    
    total_passed = 0
    total_tests = 0
    
    # Выполняем все тесты
    passed, tests = _test_file_existence()
    total_passed += passed
    total_tests += tests
    
    passed, tests = _test_import_functionality()
    total_passed += passed
    total_tests += tests
    
    # Выводим итоговые результаты
    print(f"\n📊 ИТОГОВЫЕ РЕЗУЛЬТАТЫ:")
    print(f"✅ Пройдено тестов: {total_passed}/{total_tests}")
    print(f"📈 Процент успеха: {total_passed/total_tests*100:.1f}%")
    
    if total_passed == total_tests:
        print("🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        return True
    else:
        print("⚠️  НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ")
        return False

if __name__ == "__main__":
    test_security_fixes()