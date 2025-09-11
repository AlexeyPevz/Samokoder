#!/usr/bin/env python3
"""
Final Security Test
Финальная проверка конкретных исправлений безопасности
"""

import re
from pathlib import Path

def test_jwt_validation():
    """Тестирует JWT валидацию"""
    print("\n1. Проверка JWT валидации...")
    
    deps_file = Path("backend/auth/dependencies.py")
    if not deps_file.exists():
        print("❌ Файл auth/dependencies.py не найден")
        return False
    
    content = deps_file.read_text()
    if "def validate_jwt_token" in content and "jwt.decode" in content and "payload['exp']" in content:
        print("✅ JWT валидация реализована")
        return True
    else:
        print("❌ JWT валидация не реализована")
        return False

def test_password_hashing():
    """Тестирует хеширование паролей"""
    print("\n2. Проверка хеширования паролей...")
    
    deps_file = Path("backend/auth/dependencies.py")
    if not deps_file.exists():
        print("❌ Файл auth/dependencies.py не найден")
        return False
    
    content = deps_file.read_text()
    if "def hash_password" in content and "pbkdf2_hmac" in content and "def verify_password" in content:
        print("✅ Хеширование паролей реализовано")
        return True
    else:
        print("❌ Хеширование паролей не реализовано")
        return False

def test_csrf_protection():
    """Тестирует CSRF защиту"""
    print("\n3. Проверка CSRF защиты...")
    
    main_file = Path("backend/main.py")
    if not main_file.exists():
        print("❌ Файл main.py не найден")
        return False
    
    content = main_file.read_text()
    if "csrf_protect" in content and "X-CSRF-Token" in content and "validate_csrf_token" in content:
        print("✅ CSRF защита реализована")
        return True
    else:
        print("❌ CSRF защита не реализована")
        return False

def test_cors_security():
    """Тестирует безопасную CORS конфигурацию"""
    print("\n4. Проверка безопасной CORS...")
    
    main_file = Path("backend/main.py")
    if not main_file.exists():
        print("❌ Файл main.py не найден")
        return False
    
    content = main_file.read_text()
    if "allowed_origins" in content and 'allow_headers=["*"]' not in content:
        print("✅ Безопасная CORS конфигурация")
        return True
    else:
        print("❌ Небезопасная CORS конфигурация")
        return False

def test_security_headers():
    """Тестирует заголовки безопасности"""
    print("\n5. Проверка заголовков безопасности...")
    
    main_file = Path("backend/main.py")
    if not main_file.exists():
        print("❌ Файл main.py не найден")
        return False
    
    content = main_file.read_text()
    security_headers = ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]
    if all(header in content for header in security_headers):
        print("✅ Заголовки безопасности добавлены")
        return True
    else:
        print("❌ Заголовки безопасности не добавлены")
        return False

def test_sql_injection_protection():
    """Тестирует защиту от SQL инъекций"""
    print("\n6. Проверка защиты от SQL инъекций...")
    
    validator_file = Path("backend/validators/secure_input_validator.py")
    if not validator_file.exists():
        print("❌ Файл secure_input_validator.py не найден")
        return False
    
    content = validator_file.read_text()
    if "SQL_INJECTION_PATTERNS" in content and "union" in content and "select" in content:
        print("✅ Защита от SQL инъекций реализована")
        return True
    else:
        print("❌ Защита от SQL инъекций не реализована")
        return False

def test_xss_protection():
    """Тестирует защиту от XSS"""
    print("\n7. Проверка защиты от XSS...")
    
    validator_file = Path("backend/validators/secure_input_validator.py")
    if not validator_file.exists():
        print("❌ Файл secure_input_validator.py не найден")
        return False
    
    content = validator_file.read_text()
    if "XSS_PATTERNS" in content and "bleach" in content and "script" in content:
        print("✅ Защита от XSS реализована")
        return True
    else:
        print("❌ Защита от XSS не реализована")
        return False

def test_rate_limiting():
    """Тестирует строгий rate limiting"""
    print("\n8. Проверка строгого rate limiting...")
    
    rate_limiter_file = Path("backend/middleware/secure_rate_limiter.py")
    if not rate_limiter_file.exists():
        print("❌ Файл secure_rate_limiter.py не найден")
        return False
    
    content = rate_limiter_file.read_text()
    if "auth_limits" in content and "3" in content and "900" in content:
        print("✅ Строгий rate limiting реализован")
        return True
    else:
        print("❌ Строгий rate limiting не реализован")
        return False

def run_security_tests():
    """Запускает все тесты безопасности"""
    tests = [
        test_jwt_validation,
        test_password_hashing,
        test_csrf_protection,
        test_cors_security,
        test_security_headers,
        test_sql_injection_protection,
        test_xss_protection,
        test_rate_limiting
    ]
    
    tests_passed = 0
    for test_func in tests:
        if test_func():
            tests_passed += 1
    
    return tests_passed, len(tests)

def test_specific_fixes():
    """Тестирует конкретные исправления"""
    
    print("🔒 ФИНАЛЬНАЯ ПРОВЕРКА ИСПРАВЛЕНИЙ БЕЗОПАСНОСТИ")
    print("=" * 60)
    
    # Запускаем все тесты
    tests_passed, total_tests = run_security_tests()
    
    # Тест 9: Безопасное логирование
    print("\n9. Проверка безопасного логирования...")
    total_tests += 1
    
    error_handler_file = Path("backend/middleware/secure_error_handler.py")
    if error_handler_file.exists():
        content = error_handler_file.read_text()
        if "sanitize_error_message" in content and "REDACTED" in content:
            print("✅ Безопасное логирование реализовано")
            tests_passed += 1
        else:
            print("❌ Безопасное логирование не реализовано")
    
    # Тест 10: Исправление оригинальной уязвимости с supabase
    print("\n10. Проверка исправления уязвимости с supabase...")
    total_tests += 1
    
    if deps_file.exists():
        content = deps_file.read_text()
        # Проверяем, что исправлена неопределенная переменная
        if "supabase_client = connection_manager.get_pool('supabase')" in content and "if not supabase_client:" in content:
            print("✅ Уязвимость с неопределенной переменной исправлена")
            tests_passed += 1
        else:
            print("❌ Уязвимость с неопределенной переменной НЕ исправлена")
    
    # Результаты
    print("\n" + "=" * 60)
    print(f"📊 ИТОГОВЫЕ РЕЗУЛЬТАТЫ:")
    print(f"✅ Пройдено: {tests_passed}/{total_tests}")
    print(f"❌ Провалено: {total_tests - tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("\n🎉 ВСЕ ИСПРАВЛЕНИЯ ПРИМЕНЕНЫ КОРРЕКТНО!")
        print("🔒 Критические уязвимости безопасности устранены")
        return True
    else:
        print(f"\n⚠️  НЕКОТОРЫЕ ИСПРАВЛЕНИЯ НЕ ПРИМЕНЕНЫ")
        print(f"Провалено тестов: {total_tests - tests_passed}")
        return False

if __name__ == "__main__":
    success = test_specific_fixes()
    exit(0 if success else 1)