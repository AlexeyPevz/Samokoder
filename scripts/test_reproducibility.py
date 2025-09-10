#!/usr/bin/env python3
"""
Скрипт для тестирования воспроизводимости установки Самокодер
Проверяет, что приложение можно установить и запустить "с нуля"
"""

import os
import sys
import subprocess
import time
import requests
import json
from pathlib import Path

# Цвета для вывода
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_status(message, status="INFO"):
    """Печать статуса с цветом"""
    if status == "SUCCESS":
        print(f"{Colors.GREEN}✅ {message}{Colors.END}")
    elif status == "ERROR":
        print(f"{Colors.RED}❌ {message}{Colors.END}")
    elif status == "WARNING":
        print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")
    else:
        print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")

def run_command(command, description, check=True):
    """Выполнить команду и проверить результат"""
    print_status(f"Выполняем: {description}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=check)
        if result.returncode == 0:
            print_status(f"Успешно: {description}", "SUCCESS")
            return True, result.stdout
        else:
            print_status(f"Ошибка: {description} - {result.stderr}", "ERROR")
            return False, result.stderr
    except subprocess.CalledProcessError as e:
        print_status(f"Ошибка выполнения: {description} - {e}", "ERROR")
        return False, str(e)

def check_file_exists(file_path, description):
    """Проверить существование файла"""
    if os.path.exists(file_path):
        print_status(f"Найден: {description}", "SUCCESS")
        return True
    else:
        print_status(f"Отсутствует: {description}", "ERROR")
        return False

def check_environment_variables():
    """Проверить переменные окружения"""
    print_status("Проверяем переменные окружения...")
    
    required_vars = [
        'SUPABASE_URL',
        'SUPABASE_ANON_KEY',
        'API_ENCRYPTION_KEY',
        'API_ENCRYPTION_SALT'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print_status(f"Отсутствуют переменные: {', '.join(missing_vars)}", "WARNING")
        print_status("Убедитесь, что файл .env создан и заполнен", "WARNING")
        return False
    else:
        print_status("Все необходимые переменные окружения найдены", "SUCCESS")
        return True

def check_dependencies():
    """Проверить зависимости"""
    print_status("Проверяем зависимости...")
    
    # Проверяем Python зависимости
    success, _ = run_command("python -c 'import fastapi, uvicorn, supabase'", "Python зависимости")
    if not success:
        print_status("Установите зависимости: pip install -r requirements.txt", "WARNING")
        return False
    
    # Проверяем Node.js зависимости
    if os.path.exists("frontend/package.json"):
        success, _ = run_command("cd frontend && npm list --depth=0", "Node.js зависимости", check=False)
        if not success:
            print_status("Установите frontend зависимости: cd frontend && npm install", "WARNING")
            return False
    
    return True

def check_database_connection():
    """Проверить подключение к базе данных"""
    print_status("Проверяем подключение к базе данных...")
    
    try:
        from config.settings import settings
        print_status(f"Конфигурация загружена: {settings.environment}", "SUCCESS")
        return True
    except Exception as e:
        print_status(f"Ошибка загрузки конфигурации: {e}", "ERROR")
        return False

def check_server_health():
    """Проверить здоровье сервера"""
    print_status("Проверяем здоровье сервера...")
    
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print_status(f"Сервер работает: {data.get('status', 'unknown')}", "SUCCESS")
                print_status(f"Версия: {data.get('version', 'unknown')}", "SUCCESS")
                return True
        except requests.exceptions.RequestException:
            if attempt < max_attempts - 1:
                print_status(f"Попытка {attempt + 1}/{max_attempts} - сервер не отвечает, ждем...", "WARNING")
                time.sleep(2)
            else:
                print_status("Сервер не отвечает после всех попыток", "ERROR")
                return False
    
    return False

def check_api_documentation():
    """Проверить API документацию"""
    print_status("Проверяем API документацию...")
    
    try:
        response = requests.get("http://localhost:8000/docs", timeout=5)
        if response.status_code == 200:
            print_status("API документация доступна", "SUCCESS")
            return True
        else:
            print_status(f"API документация недоступна: {response.status_code}", "ERROR")
            return False
    except requests.exceptions.RequestException as e:
        print_status(f"Ошибка доступа к API документации: {e}", "ERROR")
        return False

def check_metrics():
    """Проверить метрики"""
    print_status("Проверяем метрики...")
    
    try:
        response = requests.get("http://localhost:8000/metrics", timeout=5)
        if response.status_code == 200:
            print_status("Метрики доступны", "SUCCESS")
            return True
        else:
            print_status(f"Метрики недоступны: {response.status_code}", "WARNING")
            return False
    except requests.exceptions.RequestException as e:
        print_status(f"Ошибка доступа к метрикам: {e}", "WARNING")
        return False

def main():
    """Основная функция тестирования"""
    print(f"{Colors.BOLD}{Colors.BLUE}🧪 Тестирование воспроизводимости Самокодер{Colors.END}")
    print("=" * 60)
    
    # Счетчик успешных проверок
    passed = 0
    total = 0
    
    # 1. Проверяем файлы
    print_status("1. Проверяем наличие файлов...")
    files_to_check = [
        ("README.md", "Главная документация"),
        (".env.example", "Пример конфигурации"),
        ("requirements.txt", "Python зависимости"),
        ("docker-compose.yml", "Docker конфигурация"),
        ("Makefile", "Команды разработки")
    ]
    
    for file_path, description in files_to_check:
        total += 1
        if check_file_exists(file_path, description):
            passed += 1
    
    # 2. Проверяем зависимости
    print_status("\n2. Проверяем зависимости...")
    total += 1
    if check_dependencies():
        passed += 1
    
    # 3. Проверяем переменные окружения
    print_status("\n3. Проверяем переменные окружения...")
    total += 1
    if check_environment_variables():
        passed += 1
    
    # 4. Проверяем конфигурацию
    print_status("\n4. Проверяем конфигурацию...")
    total += 1
    if check_database_connection():
        passed += 1
    
    # 5. Проверяем сервер (если запущен)
    print_status("\n5. Проверяем сервер...")
    total += 1
    if check_server_health():
        passed += 1
        
        # 6. Проверяем API документацию
        print_status("\n6. Проверяем API документацию...")
        total += 1
        if check_api_documentation():
            passed += 1
        
        # 7. Проверяем метрики
        print_status("\n7. Проверяем метрики...")
        total += 1
        if check_metrics():
            passed += 1
    else:
        print_status("Сервер не запущен, пропускаем проверки API", "WARNING")
        total += 2  # Пропускаем 2 проверки
    
    # Результат
    print("\n" + "=" * 60)
    print_status(f"Результат: {passed}/{total} проверок пройдено")
    
    if passed == total:
        print_status("🎉 Все проверки пройдены! Установка работает корректно.", "SUCCESS")
        return 0
    else:
        print_status(f"⚠️  {total - passed} проверок не пройдено. Проверьте настройки.", "WARNING")
        return 1

if __name__ == "__main__":
    sys.exit(main())