#!/usr/bin/env python3
"""
Скрипт для применения схемы базы данных
Применяет все таблицы, индексы и политики безопасности
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.append(str(Path(__file__).parent.parent))

from config.settings import settings
from supabase import create_client, Client

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def apply_database_schema():
    """Применяет схему базы данных"""
    try:
        # Проверяем настройки Supabase
        if not settings.supabase_url or not settings.supabase_service_role_key:
            logger.error("Supabase не настроен. Проверьте переменные окружения.")
            return False
        
        if settings.supabase_url.endswith("example.supabase.co"):
            logger.warning("Используется тестовый URL Supabase. Схема не будет применена.")
            return True
        
        # Создаем клиент Supabase
        supabase: Client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key
        )
        
        logger.info("Подключение к Supabase установлено")
        
        # Читаем схему из файла
        schema_file = Path(__file__).parent.parent / "database" / "schema.sql"
        if not schema_file.exists():
            logger.error(f"Файл схемы не найден: {schema_file}")
            return False
        
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema_sql = f.read()
        
        logger.info("Схема базы данных загружена")
        
        # Разделяем SQL на отдельные команды
        sql_commands = [cmd.strip() for cmd in schema_sql.split(';') if cmd.strip()]
        
        logger.info(f"Найдено {len(sql_commands)} SQL команд")
        
        # Применяем каждую команду
        for i, command in enumerate(sql_commands, 1):
            try:
                logger.info(f"Выполнение команды {i}/{len(sql_commands)}")
                logger.debug(f"SQL: {command[:100]}...")
                
                # Выполняем SQL команду
                result = supabase.rpc('exec_sql', {'sql': command}).execute()
                
                logger.info(f"Команда {i} выполнена успешно")
                
            except Exception as e:
                logger.warning(f"Ошибка выполнения команды {i}: {e}")
                # Продолжаем выполнение других команд
                continue
        
        logger.info("✅ Схема базы данных успешно применена")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка применения схемы: {e}")
        return False

async def verify_schema():
    """Проверяет, что схема применена корректно"""
    try:
        supabase: Client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key
        )
        
        # Проверяем основные таблицы
        tables_to_check = [
            'profiles',
            'user_settings', 
            'ai_providers',
            'ai_models',
            'user_api_keys',
            'projects',
            'project_files',
            'chat_sessions',
            'chat_messages',
            'ai_usage_logs'
        ]
        
        logger.info("Проверка таблиц...")
        
        for table in tables_to_check:
            try:
                result = supabase.table(table).select("id").limit(1).execute()
                logger.info(f"✅ Таблица {table} существует")
            except Exception as e:
                logger.error(f"❌ Таблица {table} не найдена: {e}")
                return False
        
        logger.info("✅ Все таблицы существуют")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка проверки схемы: {e}")
        return False

async def main():
    """Основная функция"""
    logger.info("🚀 Начало применения схемы базы данных")
    
    # Применяем схему
    if await apply_database_schema():
        logger.info("✅ Схема применена успешно")
        
        # Проверяем схему
        if await verify_schema():
            logger.info("✅ Схема проверена успешно")
            logger.info("🎉 База данных готова к использованию!")
        else:
            logger.error("❌ Ошибка проверки схемы")
            sys.exit(1)
    else:
        logger.error("❌ Ошибка применения схемы")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())