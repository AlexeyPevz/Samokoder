#!/usr/bin/env python3
"""
Продвинутый тест API для проверки всех исправлений
"""

import requests
import json
import time
import subprocess
import sys
from pathlib import Path

def test_advanced_endpoints():
    """Тестирует продвинутые эндпойнты API"""
    
    base_url = "http://localhost:8000"
    
    print("🧪 Тестирование продвинутых API эндпойнтов...")
    
    # Тест 1: Создание проекта
    print("\n📝 Тест 1: Создание проекта")
    try:
        response = requests.post(
            f"{base_url}/api/projects",
            params={
                "project_name": "Test Project",
                "app_description": "Тестовое приложение для проверки API"
            },
            timeout=10
        )
        
        if response.status_code == 201:
            data = response.json()
            project_id = data["project_id"]
            print(f"✅ Проект создан: {project_id}")
            print(f"   Статус: {data['status']}")
            print(f"   Сообщение: {data['message']}")
        else:
            print(f"❌ Ошибка создания проекта: {response.status_code}")
            print(f"   Ответ: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка создания проекта: {e}")
        return False
    
    # Тест 2: Получение списка проектов
    print("\n📋 Тест 2: Получение списка проектов")
    try:
        response = requests.get(f"{base_url}/api/projects", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Проекты получены: {data['total']} проектов")
            print(f"   Сообщение: {data['message']}")
        else:
            print(f"❌ Ошибка получения проектов: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка получения проектов: {e}")
        return False
    
    # Тест 3: Получение деталей проекта
    print("\n🔍 Тест 3: Получение деталей проекта")
    try:
        response = requests.get(f"{base_url}/api/projects/{project_id}", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Детали проекта получены")
            print(f"   Название: {data['project']['name']}")
            print(f"   Статус: {data['project']['status']}")
            print(f"   Активен: {data['is_active']}")
        else:
            print(f"❌ Ошибка получения деталей проекта: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка получения деталей проекта: {e}")
        return False
    
    # Тест 4: Чат с проектом
    print("\n💬 Тест 4: Чат с проектом")
    try:
        chat_data = {
            "message": "Создай простой React компонент",
            "context": "development"
        }
        
        response = requests.post(
            f"{base_url}/api/projects/{project_id}/chat",
            json=chat_data,
            timeout=15
        )
        
        if response.status_code == 200:
            print("✅ Чат с проектом работает")
            # Читаем streaming ответ
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line.decode('utf-8').replace('data: ', ''))
                        print(f"   {data['type']}: {data['message']}")
                    except json.JSONDecodeError:
                        pass
        else:
            print(f"❌ Ошибка чата с проектом: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка чата с проектом: {e}")
        return False
    
    # Тест 5: Генерация проекта
    print("\n⚡ Тест 5: Генерация проекта")
    try:
        response = requests.post(
            f"{base_url}/api/projects/{project_id}/generate",
            timeout=20
        )
        
        if response.status_code == 200:
            print("✅ Генерация проекта работает")
            # Читаем streaming ответ
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line.decode('utf-8').replace('data: ', ''))
                        if data['type'] == 'progress':
                            print(f"   Прогресс: {data['progress']}% - {data['message']}")
                        elif data['type'] == 'completion':
                            print(f"   ✅ {data['message']}")
                    except json.JSONDecodeError:
                        pass
        else:
            print(f"❌ Ошибка генерации проекта: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка генерации проекта: {e}")
        return False
    
    # Тест 6: Получение файлов проекта
    print("\n📁 Тест 6: Получение файлов проекта")
    try:
        response = requests.get(f"{base_url}/api/projects/{project_id}/files", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Файлы проекта получены: {data['total_files']} файлов")
            print(f"   Сообщение: {data['message']}")
        else:
            print(f"❌ Ошибка получения файлов: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка получения файлов: {e}")
        return False
    
    # Тест 7: Получение содержимого файла
    print("\n📄 Тест 7: Получение содержимого файла")
    try:
        response = requests.get(f"{base_url}/api/projects/{project_id}/files/src/App.js", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Содержимое файла получено")
            print(f"   Путь: {data['file_path']}")
            print(f"   Размер: {data['size']} байт")
            print(f"   Сообщение: {data['message']}")
        else:
            print(f"❌ Ошибка получения содержимого файла: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка получения содержимого файла: {e}")
        return False
    
    # Тест 8: Экспорт проекта
    print("\n📦 Тест 8: Экспорт проекта")
    try:
        response = requests.get(f"{base_url}/api/projects/{project_id}/export", timeout=15)
        
        if response.status_code == 200:
            print("✅ Экспорт проекта работает")
            print(f"   Content-Type: {response.headers.get('content-type')}")
            print(f"   Размер: {len(response.content)} байт")
        else:
            print(f"❌ Ошибка экспорта проекта: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка экспорта проекта: {e}")
        return False
    
    # Тест 9: Удаление проекта
    print("\n🗑️ Тест 9: Удаление проекта")
    try:
        response = requests.delete(f"{base_url}/api/projects/{project_id}", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Проект удален")
            print(f"   Сообщение: {data['message']}")
        else:
            print(f"❌ Ошибка удаления проекта: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка удаления проекта: {e}")
        return False
    
    print("\n🎉 Все продвинутые тесты прошли успешно!")
    return True

def start_server():
    """Запускает тестовый сервер в фоновом режиме"""
    print("🚀 Запуск тестового сервера...")
    
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
            print("✅ Тестовый сервер запущен")
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
    print("🧪 Продвинутое тестирование Samokoder Backend API")
    print("=" * 60)
    
    # Проверяем, что мы в правильной директории
    if not Path("test_server.py").exists():
        print("❌ Файл test_server.py не найден. Запустите из корневой директории проекта.")
        return
    
    # Запускаем сервер
    server_process = start_server()
    
    if server_process:
        try:
            # Тестируем продвинутые API
            success = test_advanced_endpoints()
            
            if success:
                print("\n🎉 Все продвинутые тесты прошли успешно!")
                print("✅ Backend API полностью функционален")
                print("✅ Все исправления работают корректно")
            else:
                print("\n❌ Некоторые продвинутые тесты не прошли")
                
        finally:
            # Останавливаем сервер
            stop_server(server_process)
    else:
        print("❌ Не удалось запустить сервер для тестирования")

if __name__ == "__main__":
    main()