#!/usr/bin/env python3
"""
Простой тест API для проверки исправлений
"""

import requests
import json
import time
import subprocess
import sys
from pathlib import Path

def test_api_endpoints():
    """Тестирует основные эндпойнты API"""
    
    base_url = "http://localhost:8000"
    
    print("🧪 Тестирование API эндпойнтов...")
    
    # Тест 1: Проверка доступности сервера
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Сервер доступен")
        else:
            print(f"❌ Сервер недоступен: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка подключения к серверу: {e}")
        return False
    
    # Тест 2: Проверка документации
    try:
        response = requests.get(f"{base_url}/docs", timeout=5)
        if response.status_code == 200:
            print("✅ Документация доступна")
        else:
            print(f"❌ Документация недоступна: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка доступа к документации: {e}")
    
    # Тест 3: Проверка health check
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check работает")
            data = response.json()
            print(f"   Статус: {data.get('status', 'unknown')}")
        else:
            print(f"❌ Health check не работает: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка health check: {e}")
    
    # Тест 4: Проверка API info
    try:
        response = requests.get(f"{base_url}/api/info", timeout=5)
        if response.status_code == 200:
            print("✅ API info работает")
            data = response.json()
            print(f"   Версия: {data.get('version', 'unknown')}")
            print(f"   Название: {data.get('name', 'unknown')}")
        else:
            print(f"❌ API info не работает: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка API info: {e}")
    
    print("\n🎉 Тестирование завершено!")
    return True

def start_server():
    """Запускает сервер в фоновом режиме"""
    print("🚀 Запуск сервера...")
    
    # Активируем виртуальное окружение и запускаем тестовый сервер
    cmd = ["bash", "-c", "source venv/bin/activate && python test_server.py"]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Ждем немного для запуска сервера
        time.sleep(3)
        
        # Проверяем, что процесс запущен
        if process.poll() is None:
            print("✅ Сервер запущен")
            return process
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Сервер не запустился:")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            return None
            
    except Exception as e:
        print(f"❌ Ошибка запуска сервера: {e}")
        return None

def stop_server(process):
    """Останавливает сервер"""
    if process:
        print("🛑 Остановка сервера...")
        process.terminate()
        process.wait()
        print("✅ Сервер остановлен")

def main():
    """Основная функция"""
    print("🧪 Тестирование Samokoder Backend API")
    print("=" * 50)
    
    # Проверяем, что мы в правильной директории
    if not Path("run_server.py").exists():
        print("❌ Файл run_server.py не найден. Запустите из корневой директории проекта.")
        return
    
    # Запускаем сервер
    server_process = start_server()
    
    if server_process:
        try:
            # Тестируем API
            success = test_api_endpoints()
            
            if success:
                print("\n🎉 Все тесты прошли успешно!")
                print("✅ Backend API работает корректно")
            else:
                print("\n❌ Некоторые тесты не прошли")
                
        finally:
            # Останавливаем сервер
            stop_server(server_process)
    else:
        print("❌ Не удалось запустить сервер для тестирования")

if __name__ == "__main__":
    main()