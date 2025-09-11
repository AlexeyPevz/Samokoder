#!/usr/bin/env python3
"""
Скрипт для запуска тестов покрытия
Запускает все новые тесты для критических пробелов
"""

import subprocess
import sys
import os
from pathlib import Path

def run_tests(test_file: str, description: str) -> bool:
    """Запуск тестов для конкретного файла"""
    print(f"\n{'='*60}")
    print(f"🧪 {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            test_file, 
            "-v", 
            "--tb=short",
            "--no-header"
        ], capture_output=True, text=True, cwd="/workspace")
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        if result.returncode == 0:
            print(f"✅ {description} - ВСЕ ТЕСТЫ ПРОШЛИ")
            return True
        else:
            print(f"❌ {description} - ЕСТЬ ОШИБКИ")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка запуска тестов: {e}")
        return False

def main():
    """Основная функция"""
    print("🚀 ЗАПУСК ТЕСТОВ ПОКРЫТИЯ")
    print("="*60)
    
    # Список тестов для запуска
    tests = [
        ("tests/test_api_keys_p0_coverage.py", "P0 API Keys Coverage Tests"),
        ("tests/test_connection_manager_p0_coverage.py", "P0 Connection Manager Coverage Tests"),
        ("tests/test_mfa_disable_p0_coverage.py", "P0 MFA Disable Coverage Tests"),
        ("tests/test_error_handling_p1_coverage.py", "P1 Error Handling Coverage Tests"),
        ("tests/test_security_boundaries_p1_coverage.py", "P1 Security Boundaries Coverage Tests"),
        ("tests/test_integration_lifecycles_p2_coverage.py", "P2 Integration Lifecycles Coverage Tests"),
    ]
    
    results = []
    
    for test_file, description in tests:
        if os.path.exists(test_file):
            success = run_tests(test_file, description)
            results.append((description, success))
        else:
            print(f"❌ Файл {test_file} не найден")
            results.append((description, False))
    
    # Итоговая статистика
    print(f"\n{'='*60}")
    print("📊 ИТОГОВАЯ СТАТИСТИКА")
    print(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for description, success in results:
        status = "✅ ПРОШЛИ" if success else "❌ ОШИБКИ"
        print(f"{description}: {status}")
    
    print(f"\nОбщий результат: {passed}/{total} тестов прошли")
    
    if passed == total:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ! Покрытие улучшено.")
        return 0
    else:
        print("⚠️ ЕСТЬ ОШИБКИ! Требуется исправление.")
        return 1

if __name__ == "__main__":
    exit(main())