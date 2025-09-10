#!/usr/bin/env python3
"""
Скрипт для настройки переменных окружения
Создает .env файл на основе .env.example с генерацией безопасных ключей
"""

import os
import secrets
import string
import shutil
from pathlib import Path

def generate_secure_key(length=32):
    """Генерирует безопасный ключ"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_salt(length=16):
    """Генерирует соль"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def setup_environment():
    """Настройка переменных окружения"""
    print("🔧 Настройка переменных окружения...")
    
    # Проверяем наличие .env.example
    if not os.path.exists('.env.example'):
        print("❌ Файл .env.example не найден!")
        return False
    
    # Проверяем, существует ли уже .env
    if os.path.exists('.env'):
        response = input("⚠️  Файл .env уже существует. Перезаписать? (y/N): ")
        if response.lower() != 'y':
            print("Отменено.")
            return False
    
    # Копируем .env.example в .env
    shutil.copy('.env.example', '.env')
    print("✅ Скопирован .env.example в .env")
    
    # Генерируем безопасные ключи
    jwt_secret = generate_secure_key(32)
    api_encryption_key = generate_secure_key(32)
    api_encryption_salt = generate_salt(16)
    
    print("🔑 Сгенерированы безопасные ключи:")
    print(f"   JWT_SECRET: {jwt_secret}")
    print(f"   API_ENCRYPTION_KEY: {api_encryption_key}")
    print(f"   API_ENCRYPTION_SALT: {api_encryption_salt}")
    
    # Читаем .env файл
    with open('.env', 'r') as f:
        content = f.read()
    
    # Заменяем placeholder значения
    content = content.replace('your-super-secret-jwt-key-here-32-chars', jwt_secret)
    content = content.replace('your-32-character-secret-key-here', api_encryption_key)
    content = content.replace('samokoder_salt_2025', api_encryption_salt)
    
    # Записываем обновленный .env файл
    with open('.env', 'w') as f:
        f.write(content)
    
    print("✅ Файл .env обновлен с безопасными ключами")
    
    # Показываем инструкции
    print("\n📝 Следующие шаги:")
    print("1. Отредактируйте .env файл и добавьте ваши API ключи")
    print("2. Настройте SUPABASE_URL и SUPABASE_ANON_KEY")
    print("3. Добавьте ключи AI провайдеров (OpenAI, Anthropic, Groq, OpenRouter)")
    print("4. Запустите приложение: python run_server.py")
    
    return True

def main():
    """Основная функция"""
    print("🚀 Настройка Самокодер")
    print("=" * 40)
    
    if setup_environment():
        print("\n🎉 Настройка завершена успешно!")
        return 0
    else:
        print("\n❌ Настройка не удалась!")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())