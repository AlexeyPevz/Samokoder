#!/usr/bin/env python3
"""
Скрипт для запуска тестов проекта Самокодер
Поддерживает различные режимы тестирования
"""

import subprocess
import sys
import os
import argparse
from pathlib import Path

def run_command(command, description):
    """Запускает команду и выводит результат"""
    print(f"\n🔧 {description}")
    print(f"Команда: {command}")
    print("-" * 50)
    
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print("STDOUT:")
        print(result.stdout)
    
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    
    if result.returncode != 0:
        print(f"❌ Команда завершилась с ошибкой (код: {result.returncode})")
        return False
    else:
        print(f"✅ Команда выполнена успешно")
        return True

def install_dependencies():
    """Устанавливает зависимости для тестирования"""
    print("📦 Установка зависимостей для тестирования...")
    
    # Устанавливаем pytest и дополнительные пакеты
    dependencies = [
        "pytest>=7.4.0",
        "pytest-asyncio>=0.21.0",
        "pytest-cov>=4.1.0",
        "pytest-mock>=3.11.0",
        "pytest-xdist>=3.3.0",  # Для параллельного запуска тестов
        "httpx>=0.24.0",  # Для тестирования HTTP клиентов
        "faker>=19.0.0",  # Для генерации тестовых данных
    ]
    
    for dep in dependencies:
        if not run_command(f"pip install {dep}", f"Установка {dep}"):
            return False
    
    return True

def run_unit_tests(verbose=False, coverage=False, parallel=False):
    """Запускает unit тесты"""
    print("\n🧪 Запуск unit тестов...")
    
    cmd_parts = ["python -m pytest tests/"]
    
    if verbose:
        cmd_parts.append("-v")
    
    if coverage:
        cmd_parts.extend(["--cov=backend", "--cov-report=html", "--cov-report=term"])
    
    if parallel:
        cmd_parts.extend(["-n", "auto"])
    
    # Запускаем только unit тесты
    cmd_parts.extend(["-m", "unit"])
    
    command = " ".join(cmd_parts)
    
    return run_command(command, "Unit тесты")

def run_integration_tests(verbose=False):
    """Запускает integration тесты"""
    print("\n🔗 Запуск integration тестов...")
    
    cmd_parts = ["python -m pytest tests/"]
    
    if verbose:
        cmd_parts.append("-v")
    
    # Запускаем только integration тесты
    cmd_parts.extend(["-m", "integration"])
    
    command = " ".join(cmd_parts)
    
    return run_command(command, "Integration тесты")

def run_security_tests(verbose=False):
    """Запускает security тесты"""
    print("\n🔒 Запуск security тестов...")
    
    cmd_parts = ["python -m pytest tests/"]
    
    if verbose:
        cmd_parts.append("-v")
    
    # Запускаем только security тесты
    cmd_parts.extend(["-m", "security"])
    
    command = " ".join(cmd_parts)
    
    return run_command(command, "Security тесты")

def run_all_tests(verbose=False, coverage=False, parallel=False):
    """Запускает все тесты"""
    print("\n🚀 Запуск всех тестов...")
    
    cmd_parts = ["python -m pytest tests/"]
    
    if verbose:
        cmd_parts.append("-v")
    
    if coverage:
        cmd_parts.extend(["--cov=backend", "--cov-report=html", "--cov-report=term"])
    
    if parallel:
        cmd_parts.extend(["-n", "auto"])
    
    command = " ".join(cmd_parts)
    
    return run_command(command, "Все тесты")

def run_specific_test(test_path, verbose=False):
    """Запускает конкретный тест"""
    print(f"\n🎯 Запуск теста: {test_path}")
    
    cmd_parts = ["python -m pytest", test_path]
    
    if verbose:
        cmd_parts.append("-v")
    
    command = " ".join(cmd_parts)
    
    return run_command(command, f"Тест {test_path}")

def run_linting():
    """Запускает линтеры"""
    print("\n🔍 Запуск линтеров...")
    
    # Проверяем наличие линтеров
    linters = [
        ("flake8", "flake8 backend/ tests/"),
        ("black", "black --check backend/ tests/"),
        ("isort", "isort --check-only backend/ tests/"),
        ("mypy", "mypy backend/")
    ]
    
    results = []
    for linter_name, command in linters:
        print(f"\n🔧 Запуск {linter_name}...")
        result = run_command(command, f"{linter_name} проверка")
        results.append((linter_name, result))
    
    return all(result for _, result in results)

def generate_test_report():
    """Генерирует отчет о тестах"""
    print("\n📊 Генерация отчета о тестах...")
    
    # Создаем директорию для отчетов
    reports_dir = Path("test_reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Генерируем HTML отчет
    command = "python -m pytest tests/ --html=test_reports/report.html --self-contained-html"
    success = run_command(command, "Генерация HTML отчета")
    
    if success:
        print(f"📄 Отчет сохранен в: {reports_dir.absolute()}/report.html")
    
    return success

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description="Запуск тестов проекта Самокодер")
    parser.add_argument("--type", choices=["unit", "integration", "security", "all"], 
                       default="all", help="Тип тестов для запуска")
    parser.add_argument("--test", help="Путь к конкретному тесту")
    parser.add_argument("--verbose", "-v", action="store_true", help="Подробный вывод")
    parser.add_argument("--coverage", "-c", action="store_true", help="Покрытие кода")
    parser.add_argument("--parallel", "-p", action="store_true", help="Параллельный запуск")
    parser.add_argument("--lint", action="store_true", help="Запуск линтеров")
    parser.add_argument("--install", action="store_true", help="Установка зависимостей")
    parser.add_argument("--report", action="store_true", help="Генерация отчета")
    
    args = parser.parse_args()
    
    print("🧪 ТЕСТИРОВАНИЕ ПРОЕКТА САМОКОДЕР")
    print("=" * 50)
    
    success = True
    
    # Установка зависимостей
    if args.install:
        success &= install_dependencies()
    
    # Запуск линтеров
    if args.lint:
        success &= run_linting()
    
    # Запуск тестов
    if args.test:
        success &= run_specific_test(args.test, args.verbose)
    elif args.type == "unit":
        success &= run_unit_tests(args.verbose, args.coverage, args.parallel)
    elif args.type == "integration":
        success &= run_integration_tests(args.verbose)
    elif args.type == "security":
        success &= run_security_tests(args.verbose)
    elif args.type == "all":
        success &= run_all_tests(args.verbose, args.coverage, args.parallel)
    
    # Генерация отчета
    if args.report:
        success &= generate_test_report()
    
    # Итоговый результат
    print("\n" + "=" * 50)
    if success:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ УСПЕШНО!")
        sys.exit(0)
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОШЛИ!")
        sys.exit(1)

if __name__ == "__main__":
    main()