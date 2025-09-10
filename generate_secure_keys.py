#!/usr/bin/env python3
"""
Генератор безопасных ключей для production окружения
Использует криптографически стойкие методы генерации
"""

import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def generate_secure_string(length: int, include_symbols: bool = True) -> str:
    """Генерирует криптографически стойкую строку"""
    if include_symbols:
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
    else:
        characters = string.ascii_letters + string.digits
    
    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_fernet_key() -> str:
    """Генерирует ключ для Fernet шифрования"""
    return Fernet.generate_key().decode()

def generate_jwt_secret() -> str:
    """Генерирует JWT секрет"""
    return secrets.token_urlsafe(32)

def generate_api_encryption_key() -> str:
    """Генерирует 32-символьный ключ для шифрования API"""
    return generate_secure_string(32, include_symbols=False)

def generate_salt() -> str:
    """Генерирует соль для PBKDF2"""
    return generate_secure_string(16, include_symbols=False)

def generate_csrf_secret() -> str:
    """Генерирует CSRF секрет"""
    return secrets.token_urlsafe(32)

def main():
    """Генерирует все необходимые ключи"""
    print("🔐 ГЕНЕРАЦИЯ БЕЗОПАСНЫХ КЛЮЧЕЙ ДЛЯ PRODUCTION")
    print("=" * 60)
    
    keys = {
        "API_ENCRYPTION_KEY": generate_api_encryption_key(),
        "API_ENCRYPTION_SALT": generate_salt(),
        "JWT_SECRET": generate_jwt_secret(),
        "CSRF_SECRET": generate_csrf_secret(),
        "FERNET_KEY": generate_fernet_key(),
    }
    
    print("\n📋 СГЕНЕРИРОВАННЫЕ КЛЮЧИ:")
    print("-" * 40)
    
    for key_name, key_value in keys.items():
        print(f"{key_name}={key_value}")
    
    print("\n🔒 РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:")
    print("-" * 40)
    print("1. Сохраните эти ключи в безопасном месте")
    print("2. НЕ коммитьте их в Git")
    print("3. Используйте переменные окружения в production")
    print("4. Регулярно ротируйте ключи (каждые 90 дней)")
    print("5. Используйте разные ключи для разных окружений")
    
    print("\n📝 ДЛЯ .env ФАЙЛА:")
    print("-" * 40)
    for key_name, key_value in keys.items():
        print(f"{key_name}={key_value}")
    
    # Проверяем силу ключей
    print("\n✅ ПРОВЕРКА СИЛЫ КЛЮЧЕЙ:")
    print("-" * 40)
    
    for key_name, key_value in keys.items():
        entropy = len(key_value) * 4  # Примерная энтропия
        strength = "ОТЛИЧНО" if entropy >= 128 else "ХОРОШО" if entropy >= 64 else "СЛАБО"
        print(f"{key_name}: {strength} (энтропия: ~{entropy} бит)")
    
    print("\n🎯 КЛЮЧИ ГОТОВЫ К ИСПОЛЬЗОВАНИЮ В PRODUCTION!")

if __name__ == "__main__":
    main()