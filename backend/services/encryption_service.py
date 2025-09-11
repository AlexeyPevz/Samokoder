"""
Сервис шифрования для API ключей и чувствительных данных
Использует PBKDF2 для безопасного шифрования
"""

import os
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class EncryptionService:
    """Сервис для шифрования и расшифровки данных"""
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Инициализация сервиса шифрования
        
        Args:
            master_key: Главный ключ для шифрования. Если не указан, генерируется новый.
        """
        self.master_key = master_key or os.getenv("API_ENCRYPTION_KEY")
        if not self.master_key:
            logger.warning("API_ENCRYPTION_KEY не найден, генерируется новый ключ")
            self.master_key = self._generate_master_key()
        
        # Создаем ключ для Fernet из master_key
        self.fernet_key = self._derive_fernet_key(self.master_key)
        self.cipher_suite = Fernet(self.fernet_key)
    
    def _generate_master_key(self) -> str:
        """Генерирует новый главный ключ"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    
    def _derive_fernet_key(self, master_key: str) -> bytes:
        """Создает ключ Fernet из главного ключа"""
        # Используем соль из переменной окружения или генерируем
        salt = os.getenv("API_ENCRYPTION_SALT", "samokoder_salt_2025").encode()
        
        # Создаем ключ с помощью PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return key
    
    def encrypt(self, data: str) -> str:
        """
        Шифрует данные
        
        Args:
            data: Строка для шифрования
            
        Returns:
            Зашифрованная строка в base64
        """
        try:
            if not data:
                return ""
            
            # Шифруем данные
            encrypted_data = self.cipher_suite.encrypt(data.encode())
            
            # Возвращаем в base64
            return base64.urlsafe_b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"Ошибка шифрования: {e}")
            raise ValueError(f"Не удалось зашифровать данные: {e}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Расшифровывает данные
        
        Args:
            encrypted_data: Зашифрованная строка в base64
            
        Returns:
            Расшифрованная строка
        """
        try:
            if not encrypted_data:
                return ""
            
            # Декодируем из base64
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            
            # Расшифровываем
            decrypted_data = self.cipher_suite.decrypt(encrypted_bytes)
            
            return decrypted_data.decode()
            
        except Exception as e:
            logger.error(f"Ошибка расшифровки: {e}")
            raise ValueError(f"Не удалось расшифровать данные: {e}")
    
    def encrypt_api_key(self, api_key: str, user_id: str) -> str:
        """
        Шифрует API ключ пользователя
        
        Args:
            api_key: API ключ для шифрования
            user_id: ID пользователя (для дополнительной безопасности)
            
        Returns:
            Зашифрованный API ключ
        """
        # Добавляем user_id для дополнительной безопасности
        data_to_encrypt = f"{user_id}:{api_key}"
        return self.encrypt(data_to_encrypt)
    
    def decrypt_api_key(self, encrypted_api_key: str, user_id: str) -> str:
        """
        Расшифровывает API ключ пользователя
        
        Args:
            encrypted_api_key: Зашифрованный API ключ
            user_id: ID пользователя (для проверки)
            
        Returns:
            Расшифрованный API ключ
        """
        try:
            decrypted_data = self.decrypt(encrypted_api_key)
            
            # Проверяем, что данные принадлежат пользователю
            if not decrypted_data.startswith(f"{user_id}:"):
                raise ValueError("API ключ не принадлежит пользователю")
            
            # Извлекаем API ключ
            api_key = decrypted_data[len(f"{user_id}:"):]
            return api_key
            
        except Exception as e:
            logger.error(f"Ошибка расшифровки API ключа: {e}")
            raise ValueError(f"Не удалось расшифровать API ключ: {e}")
    
    def get_key_last_4(self, api_key: str) -> str:
        """
        Возвращает последние 4 символа API ключа для отображения
        
        Args:
            api_key: API ключ
            
        Returns:
            Последние 4 символа ключа
        """
        if not api_key or len(api_key) < 4:
            return "****"
        
        return api_key[-4:]

# Глобальный экземпляр сервиса шифрования
encryption_service = EncryptionService()

def get_encryption_service() -> EncryptionService:
    """Возвращает экземпляр сервиса шифрования"""
    return encryption_service