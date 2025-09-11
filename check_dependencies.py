#!/usr/bin/env python3
"""
Скрипт для проверки уязвимостей зависимостей
"""

import subprocess
import json
import sys
from typing import Dict, List, Any

def run_command(command: str) -> tuple[bool, str]:
    """Выполняет команду и возвращает результат"""
    try:
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)

def check_pip_audit():
    """Проверяет уязвимости с помощью pip-audit"""
    print("🔍 Проверка уязвимостей с помощью pip-audit...")
    
    # Устанавливаем pip-audit если не установлен
    success, output = run_command("pip install pip-audit")
    if not success:
        print(f"❌ Ошибка установки pip-audit: {output}")
        return False
    
    # Запускаем проверку
    success, output = run_command("pip-audit --format=json")
    if not success:
        print(f"❌ Ошибка выполнения pip-audit: {output}")
        return False
    
    try:
        vulnerabilities = json.loads(output)
        if vulnerabilities:
            print(f"⚠️  Найдено {len(vulnerabilities)} уязвимостей:")
            for vuln in vulnerabilities:
                print(f"  - {vuln.get('package', 'Unknown')}: {vuln.get('vulnerability', 'Unknown')}")
            return False
        else:
            print("✅ Уязвимости не найдены")
            return True
    except json.JSONDecodeError:
        print(f"❌ Ошибка парсинга JSON: {output}")
        return False

def check_safety():
    """Проверяет уязвимости с помощью safety"""
    print("\n🔍 Проверка уязвимостей с помощью safety...")
    
    # Устанавливаем safety если не установлен
    success, output = run_command("pip install safety")
    if not success:
        print(f"❌ Ошибка установки safety: {output}")
        return False
    
    # Запускаем проверку
    success, output = run_command("safety check --json")
    if not success:
        print(f"❌ Ошибка выполнения safety: {output}")
        return False
    
    try:
        vulnerabilities = json.loads(output)
        if vulnerabilities:
            print(f"⚠️  Найдено {len(vulnerabilities)} уязвимостей:")
            for vuln in vulnerabilities:
                print(f"  - {vuln.get('package_name', 'Unknown')}: {vuln.get('advisory', 'Unknown')}")
            return False
        else:
            print("✅ Уязвимости не найдены")
            return True
    except json.JSONDecodeError:
        print(f"❌ Ошибка парсинга JSON: {output}")
        return False

def check_outdated_packages():
    """Проверяет устаревшие пакеты"""
    print("\n🔍 Проверка устаревших пакетов...")
    
    success, output = run_command("pip list --outdated --format=json")
    if not success:
        print(f"❌ Ошибка получения списка пакетов: {output}")
        return False
    
    try:
        outdated = json.loads(output)
        if outdated:
            print(f"⚠️  Найдено {len(outdated)} устаревших пакетов:")
            for package in outdated:
                print(f"  - {package['name']}: {package['version']} -> {package['latest_version']}")
            return False
        else:
            print("✅ Все пакеты актуальны")
            return True
    except json.JSONDecodeError:
        print(f"❌ Ошибка парсинга JSON: {output}")
        return False

def check_requirements_security():
    """Проверяет безопасность requirements.txt"""
    print("\n🔍 Проверка безопасности requirements.txt...")
    
    try:
        with open("requirements.txt", "r") as f:
            requirements = f.read()
        
        # Проверяем на подозрительные пакеты
        suspicious_packages = [
            "requests[security]",  # Устаревший способ
            "urllib3<1.26",       # Устаревшая версия
            "cryptography<3.0",   # Устаревшая версия
        ]
        
        issues = []
        for package in suspicious_packages:
            if package in requirements:
                issues.append(f"Подозрительный пакет: {package}")
        
        if issues:
            print("⚠️  Найдены проблемы в requirements.txt:")
            for issue in issues:
                print(f"  - {issue}")
            return False
        else:
            print("✅ requirements.txt выглядит безопасно")
            return True
            
    except FileNotFoundError:
        print("❌ Файл requirements.txt не найден")
        return False
    except Exception as e:
        print(f"❌ Ошибка чтения requirements.txt: {e}")
        return False

def main():
    """Основная функция"""
    print("🛡️  Проверка безопасности зависимостей")
    print("=" * 50)
    
    results = []
    
    # Проверяем различные аспекты безопасности
    results.append(check_requirements_security())
    results.append(check_outdated_packages())
    results.append(check_safety())
    results.append(check_pip_audit())
    
    # Подводим итоги
    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ ПРОВЕРКИ")
    print("=" * 50)
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print("✅ Все проверки пройдены успешно!")
        return 0
    else:
        print(f"⚠️  Пройдено {passed} из {total} проверок")
        print("❌ Рекомендуется исправить найденные проблемы")
        return 1

if __name__ == "__main__":
    sys.exit(main())