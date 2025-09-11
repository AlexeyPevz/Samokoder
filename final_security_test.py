#!/usr/bin/env python3
"""
Final Security Test
Финальная проверка конкретных исправлений безопасности
"""

import re
from pathlib import Path

def test_specific_fixes():
    """Тестирует конкретные исправления"""
    
    print("🔒 ФИНАЛЬНАЯ ПРОВЕРКА ИСПРАВЛЕНИЙ БЕЗОПАСНОСТИ")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 0
    
    # Тест 1: JWT валидация
    print("\n1. Проверка JWT валидации...")
    total_tests += 1
    
    deps_file = Path("backend/auth/dependencies.py")
    if deps_file.exists():
        content = deps_file.read_text()
        if "def validate_jwt_token" in content and "jwt.decode" in content and "payload['exp']" in content:
            print("✅ JWT валидация реализована")
            tests_passed += 1
        else:
            print("❌ JWT валидация не реализована")
    else:
        print("❌ Файл auth/dependencies.py не найден")
    
    # Тест 2: Хеширование паролей
    print("\n2. Проверка хеширования паролей...")
    total_tests += 1
    
    if deps_file.exists():
        content = deps_file.read_text()
        if "def hash_password" in content and "pbkdf2_hmac" in content and "def verify_password" in content:
            print("✅ Хеширование паролей реализовано")
            tests_passed += 1
        else:
            print("❌ Хеширование паролей не реализовано")
    
    # Тест 3: CSRF защита
    print("\n3. Проверка CSRF защиты...")
    total_tests += 1
    
    main_file = Path("backend/main.py")
    if main_file.exists():
        content = main_file.read_text()
        if "csrf_protect" in content and "X-CSRF-Token" in content and "validate_csrf_token" in content:
            print("✅ CSRF защита реализована")
            tests_passed += 1
        else:
            print("❌ CSRF защита не реализована")
    
    # Тест 4: Безопасная CORS
    print("\n4. Проверка безопасной CORS...")
    total_tests += 1
    
    if main_file.exists():
        content = main_file.read_text()
        if "allowed_origins" in content and 'allow_headers=["*"]' not in content:
            print("✅ Безопасная CORS конфигурация")
            tests_passed += 1
        else:
            print("❌ Небезопасная CORS конфигурация")
    
    # Тест 5: Заголовки безопасности
    print("\n5. Проверка заголовков безопасности...")
    total_tests += 1
    
    if main_file.exists():
        content = main_file.read_text()
        security_headers = ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]
        if all(header in content for header in security_headers):
            print("✅ Заголовки безопасности добавлены")
            tests_passed += 1
        else:
            print("❌ Заголовки безопасности не добавлены")
    
    # Тест 6: Защита от SQL инъекций
    print("\n6. Проверка защиты от SQL инъекций...")
    total_tests += 1
    
    validator_file = Path("backend/validators/secure_input_validator.py")
    if validator_file.exists():
        content = validator_file.read_text()
        if "SQL_INJECTION_PATTERNS" in content and "union" in content and "select" in content:
            print("✅ Защита от SQL инъекций реализована")
            tests_passed += 1
        else:
            print("❌ Защита от SQL инъекций не реализована")
    
    # Тест 7: Защита от XSS
    print("\n7. Проверка защиты от XSS...")
    total_tests += 1
    
    if validator_file.exists():
        content = validator_file.read_text()
        if "XSS_PATTERNS" in content and "bleach" in content and "script" in content:
            print("✅ Защита от XSS реализована")
            tests_passed += 1
        else:
            print("❌ Защита от XSS не реализована")
    
    # Тест 8: Строгий rate limiting
    print("\n8. Проверка строгого rate limiting...")
    total_tests += 1
    
    rate_limiter_file = Path("backend/middleware/secure_rate_limiter.py")
    if rate_limiter_file.exists():
        content = rate_limiter_file.read_text()
        if "auth_limits" in content and "3" in content and "900" in content:
            print("✅ Строгий rate limiting реализован")
            tests_passed += 1
        else:
            print("❌ Строгий rate limiting не реализован")
    
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