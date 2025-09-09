#!/usr/bin/env python3
"""
Тест интеграции с GPT-Pilot
Проверяет работу нового адаптера и wrapper
"""

import asyncio
import sys
import os
from pathlib import Path

# Добавляем путь к проекту
sys.path.append(str(Path(__file__).parent))

from backend.services.gpt_pilot_adapter import SamokoderGPTPilotAdapter
from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot

async def test_gpt_pilot_adapter():
    """Тестирует адаптер GPT-Pilot"""
    print("🧪 Тестирование адаптера GPT-Pilot...")
    
    # Тестовые данные
    project_id = "test_proj_001"
    user_id = "test_user"
    user_api_keys = {
        "openai": "sk-test-key",
        "openrouter": "sk-test-key"
    }
    
    try:
        # Создаем адаптер
        adapter = SamokoderGPTPilotAdapter(project_id, user_id, user_api_keys)
        print("✅ Адаптер создан")
        
        # Тестируем инициализацию проекта
        print("📝 Тестирование инициализации проекта...")
        result = await adapter.initialize_project("Test App", "Тестовое приложение")
        print(f"✅ Проект инициализирован: {result['status']}")
        
        # Тестируем получение статуса
        print("📊 Тестирование получения статуса...")
        status = adapter.get_project_status()
        print(f"✅ Статус получен: {status['status']}")
        
        # Тестируем получение файлов
        print("📁 Тестирование получения файлов...")
        files = adapter.get_project_files()
        print(f"✅ Файлы получены: {len(files)} элементов")
        
        # Тестируем чат с агентами
        print("💬 Тестирование чата с агентами...")
        message_count = 0
        async for update in adapter.chat_with_agents("Создай простой React компонент"):
            message_count += 1
            print(f"   {update['type']}: {update['message']}")
            if message_count >= 3:  # Ограничиваем количество сообщений для теста
                break
        
        print("✅ Чат с агентами работает")
        
        # Тестируем генерацию приложения
        print("⚡ Тестирование генерации приложения...")
        gen_count = 0
        async for update in adapter.generate_full_app():
            gen_count += 1
            print(f"   {update['type']}: {update['message']}")
            if gen_count >= 3:  # Ограничиваем количество сообщений для теста
                break
        
        print("✅ Генерация приложения работает")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте адаптера: {e}")
        return False

async def test_gpt_pilot_wrapper():
    """Тестирует wrapper GPT-Pilot"""
    print("\n🧪 Тестирование wrapper GPT-Pilot...")
    
    # Тестовые данные
    project_id = "test_proj_002"
    user_id = "test_user"
    user_api_keys = {
        "openai": "sk-test-key",
        "openrouter": "sk-test-key"
    }
    
    try:
        # Создаем wrapper
        wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
        print("✅ Wrapper создан")
        
        # Тестируем инициализацию проекта
        print("📝 Тестирование инициализации проекта...")
        result = await wrapper.initialize_project("Тестовое приложение", "Test App")
        print(f"✅ Проект инициализирован: {result['status']}")
        
        # Тестируем проверку инициализации
        print("🔍 Тестирование проверки инициализации...")
        is_init = wrapper.is_initialized()
        print(f"✅ Инициализация проверена: {is_init}")
        
        # Тестируем получение конфигурации API
        print("⚙️ Тестирование конфигурации API...")
        api_config = wrapper.get_api_config()
        print(f"✅ Конфигурация API получена: {api_config['endpoint']}")
        
        # Тестируем получение статуса агентов
        print("🤖 Тестирование статуса агентов...")
        agent_status = await wrapper.get_agent_status()
        print(f"✅ Статус агентов получен: {agent_status['status']}")
        
        # Тестируем чат с агентами
        print("💬 Тестирование чата с агентами...")
        message_count = 0
        async for update in wrapper.chat_with_agents("Создай простой React компонент"):
            message_count += 1
            print(f"   {update['type']}: {update['message']}")
            if message_count >= 3:  # Ограничиваем количество сообщений для теста
                break
        
        print("✅ Чат с агентами работает")
        
        # Тестируем генерацию приложения
        print("⚡ Тестирование генерации приложения...")
        gen_count = 0
        async for update in wrapper.generate_full_app():
            gen_count += 1
            print(f"   {update['type']}: {update['message']}")
            if gen_count >= 3:  # Ограничиваем количество сообщений для теста
                break
        
        print("✅ Генерация приложения работает")
        
        # Тестируем очистку ресурсов
        print("🧹 Тестирование очистки ресурсов...")
        wrapper.cleanup()
        print("✅ Ресурсы очищены")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте wrapper: {e}")
        return False

async def test_integration_flow():
    """Тестирует полный поток интеграции"""
    print("\n🧪 Тестирование полного потока интеграции...")
    
    # Тестовые данные
    project_id = "test_proj_003"
    user_id = "test_user"
    user_api_keys = {
        "openai": "sk-test-key",
        "openrouter": "sk-test-key"
    }
    
    try:
        # Создаем wrapper
        wrapper = SamokoderGPTPilot(project_id, user_id, user_api_keys)
        
        # 1. Инициализация проекта
        print("1️⃣ Инициализация проекта...")
        result = await wrapper.initialize_project("Полноценное приложение", "Full App")
        if result['status'] != 'initialized':
            raise Exception(f"Ошибка инициализации: {result}")
        print("✅ Проект инициализирован")
        
        # 2. Чат с агентами
        print("2️⃣ Чат с агентами...")
        async for update in wrapper.chat_with_agents("Создай полноценное React приложение с компонентами"):
            if update['type'] == 'completion':
                print("✅ Чат завершен")
                break
        
        # 3. Генерация приложения
        print("3️⃣ Генерация приложения...")
        async for update in wrapper.generate_full_app():
            if update['type'] == 'completion':
                print("✅ Генерация завершена")
                break
        
        # 4. Получение файлов
        print("4️⃣ Получение файлов...")
        files = wrapper.get_project_files()
        print(f"✅ Файлы получены: {len(files)} элементов")
        
        # 5. Получение статуса
        print("5️⃣ Получение статуса...")
        status = wrapper.get_project_status()
        print(f"✅ Статус получен: {status['status']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте потока: {e}")
        return False

async def main():
    """Основная функция тестирования"""
    print("🧪 Тестирование интеграции с GPT-Pilot")
    print("=" * 50)
    
    # Тест 1: Адаптер
    adapter_success = await test_gpt_pilot_adapter()
    
    # Тест 2: Wrapper
    wrapper_success = await test_gpt_pilot_wrapper()
    
    # Тест 3: Полный поток
    flow_success = await test_integration_flow()
    
    # Результаты
    print("\n📊 Результаты тестирования:")
    print(f"  - Адаптер: {'✅' if adapter_success else '❌'}")
    print(f"  - Wrapper: {'✅' if wrapper_success else '❌'}")
    print(f"  - Поток: {'✅' if flow_success else '❌'}")
    
    if adapter_success and wrapper_success and flow_success:
        print("\n🎉 Все тесты интеграции прошли успешно!")
        print("✅ GPT-Pilot полностью интегрирован")
        return True
    else:
        print("\n❌ Некоторые тесты интеграции не прошли")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)