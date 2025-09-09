#!/usr/bin/env python3
"""
Генератор безопасных ключей для проекта Самокодер
"""

import secrets
import string
import os

def generate_key(length: int) -> str:
    """Генерирует случайный ключ заданной длины"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_secure_key() -> str:
    """Генерирует безопасный ключ для API"""
    return secrets.token_urlsafe(32)

def main():
    """Генерирует все необходимые ключи безопасности"""
    print("🔐 Генерация безопасных ключей для проекта Самокодер")
    print("=" * 50)
    
    # Генерируем ключи
    api_encryption_key = generate_key(32)
    api_encryption_salt = generate_key(16)
    secret_key = generate_secure_key()
    
    print("\n📋 Сгенерированные ключи:")
    print(f"API_ENCRYPTION_KEY={api_encryption_key}")
    print(f"API_ENCRYPTION_SALT={api_encryption_salt}")
    print(f"SECRET_KEY={secret_key}")
    
    print("\n⚠️ ВАЖНО:")
    print("1. Сохраните эти ключи в безопасном месте")
    print("2. Замените placeholder значения в .env файле")
    print("3. Никогда не коммитьте реальные ключи в Git")
    print("4. Используйте разные ключи для разных окружений")
    
    # Создаем файл с ключами (только для разработки)
    if input("\nСоздать файл .env.keys для разработки? (y/n): ").lower() == 'y':
        with open('.env.keys', 'w') as f:
            f.write(f"# Безопасные ключи для разработки\n")
            f.write(f"API_ENCRYPTION_KEY={api_encryption_key}\n")
            f.write(f"API_ENCRYPTION_SALT={api_encryption_salt}\n")
            f.write(f"SECRET_KEY={secret_key}\n")
        
        print("✅ Файл .env.keys создан")
        print("⚠️ Не коммитьте этот файл в Git!")
    
    print("\n🎯 Следующие шаги:")
    print("1. Обновите .env файл с новыми ключами")
    print("2. Настройте Supabase проект")
    print("3. Получите реальные Supabase ключи")
    print("4. Запустите comprehensive тест снова")

if __name__ == "__main__":
    main()