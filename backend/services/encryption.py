import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional

from config.settings import settings

class APIKeyEncryption:
    """
    Сервис для шифрования и расшифровки API ключей пользователей
    """
    
    def __init__(self):
        # Получаем master key из переменных окружения
        self.master_password = settings.api_encryption_key.encode()
        self.salt = settings.api_encryption_salt.encode()
        
        # Создаем ключ шифрования
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,  # Высокое количество итераций для защиты от брутфорса
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password))
        self.fernet = Fernet(key)
    
    def encrypt_api_key(self, api_key: str) -> str:
        """
        Шифрует API ключ для безопасного хранения в базе данных
        
        Args:
            api_key: Исходный API ключ
            
        Returns:
            Зашифрованный ключ в base64 формате
        """
        try:
            encrypted = self.fernet.encrypt(api_key.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Ошибка шифрования API ключа: {str(e)}")
    
    def decrypt_api_key(self, encrypted_key: str) -> str:
        """
        Расшифровывает API ключ для использования
        
        Args:
            encrypted_key: Зашифрованный ключ в base64 формате
            
        Returns:
            Исходный API ключ
        """
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_key.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Ошибка расшифровки API ключа: {str(e)}")
    
    def get_last_4_chars(self, api_key: str) -> str:
        """
        Возвращает последние 4 символа для отображения пользователю
        
        Args:
            api_key: Исходный API ключ
            
        Returns:
            Маскированный ключ вида "...abcd"
        """
        if len(api_key) < 4:
            return "..."
        return f"...{api_key[-4:]}"
    
    def mask_api_key(self, api_key: str, visible_chars: int = 4) -> str:
        """
        Маскирует API ключ для безопасного отображения
        
        Args:
            api_key: Исходный API ключ
            visible_chars: Количество видимых символов в конце
            
        Returns:
            Маскированный ключ вида "****...abcd"
        """
        if len(api_key) <= visible_chars:
            return "*" * len(api_key)
        
        masked_length = len(api_key) - visible_chars
        return "*" * masked_length + api_key[-visible_chars:]
    
    def validate_api_key_format(self, api_key: str, provider: str) -> bool:
        """
        Валидирует формат API ключа для конкретного провайдера
        
        Args:
            api_key: API ключ для проверки
            provider: Название провайдера
            
        Returns:
            True если формат корректный
        """
        if not api_key or len(api_key.strip()) == 0:
            return False
        
        # Базовые проверки длины
        if len(api_key) < 10:
            return False
        
        # Проверки для конкретных провайдеров
        if provider.lower() == "openai":
            # OpenAI ключи начинаются с sk-
            return api_key.startswith("sk-") and len(api_key) >= 20
        
        elif provider.lower() == "anthropic":
            # Anthropic ключи начинаются с sk-ant-
            return api_key.startswith("sk-ant-") and len(api_key) >= 20
        
        elif provider.lower() == "openrouter":
            # OpenRouter ключи начинаются с sk-or-
            return api_key.startswith("sk-or-") and len(api_key) >= 20
        
        elif provider.lower() == "groq":
            # Groq ключи обычно длинные
            return len(api_key) >= 20
        
        # Для неизвестных провайдеров - базовая проверка
        return len(api_key) >= 10 and api_key.isalnum()

# Создаем глобальный экземпляр сервиса шифрования
encryption_service = APIKeyEncryption()