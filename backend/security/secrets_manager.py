"""
Secret Management для безопасного хранения и управления секретами
"""
import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecretsProvider(ABC):
    """Абстрактный базовый класс для провайдеров секретов"""
    
    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        """Получить секрет по ключу"""
        pass
    
    @abstractmethod
    async def set_secret(self, key: str, value: str) -> bool:
        """Установить секрет"""
        pass
    
    @abstractmethod
    async def delete_secret(self, key: str) -> bool:
        """Удалить секрет"""
        pass

class EnvironmentSecretsProvider(SecretsProvider):
    """Провайдер секретов из переменных окружения (для development)"""
    
    def __init__(self, prefix: str = ""):
        self.prefix = prefix
    
    async def get_secret(self, key: str) -> Optional[str]:
        """Получить секрет из переменной окружения"""
        env_key = f"{self.prefix}{key}".upper()
        return os.getenv(env_key)
    
    async def set_secret(self, key: str, value: str) -> bool:
        """Установить секрет в переменную окружения"""
        env_key = f"{self.prefix}{key}".upper()
        os.environ[env_key] = value
        return True
    
    async def delete_secret(self, key: str) -> bool:
        """Удалить секрет из переменных окружения"""
        env_key = f"{self.prefix}{key}".upper()
        if env_key in os.environ:
            del os.environ[env_key]
        return True

class FileSecretsProvider(SecretsProvider):
    """Провайдер секретов из файла (для development/staging)"""
    
    def __init__(self, secrets_file: str = ".secrets.json"):
        self.secrets_file = secrets_file
        self._secrets: Dict[str, str] = {}
        self._load_secrets()
    
    def _load_secrets(self):
        """Загрузить секреты из файла"""
        if os.path.exists(self.secrets_file):
            try:
                with open(self.secrets_file, 'r') as f:
                    self._secrets = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load secrets file: {e}")
                self._secrets = {}
    
    def _save_secrets(self):
        """Сохранить секреты в файл"""
        try:
            with open(self.secrets_file, 'w') as f:
                json.dump(self._secrets, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save secrets file: {e}")
    
    async def get_secret(self, key: str) -> Optional[str]:
        """Получить секрет из файла"""
        return self._secrets.get(key)
    
    async def set_secret(self, key: str, value: str) -> bool:
        """Установить секрет в файл"""
        self._secrets[key] = value
        self._save_secrets()
        return True
    
    async def delete_secret(self, key: str) -> bool:
        """Удалить секрет из файла"""
        if key in self._secrets:
            del self._secrets[key]
            self._save_secrets()
        return True

class AWSSecretsManagerProvider(SecretsProvider):
    """Провайдер секретов из AWS Secrets Manager (для production)"""
    
    def __init__(self, region: str = "us-east-1", prefix: str = "/samokoder/"):
        self.region = region
        self.prefix = prefix
        self._client = None
    
    def _get_client(self):
        """Получить AWS клиент"""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client('secretsmanager', region_name=self.region)
            except ImportError:
                logger.error("boto3 not installed. Install with: pip install boto3")
                raise
        return self._client
    
    async def get_secret(self, key: str) -> Optional[str]:
        """Получить секрет из AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"{self.prefix}{key}"
            response = client.get_secret_value(SecretId=secret_name)
            return response['SecretString']
        except Exception as e:
            logger.error(f"Failed to get secret {key} from AWS: {e}")
            return None
    
    async def set_secret(self, key: str, value: str) -> bool:
        """Установить секрет в AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"{self.prefix}{key}"
            client.create_secret(
                Name=secret_name,
                SecretString=value,
                Description=f"Secret for {key}"
            )
            return True
        except client.exceptions.ResourceExistsException:
            # Секрет уже существует, обновляем его
            try:
                client.update_secret(
                    SecretId=secret_name,
                    SecretString=value
                )
                return True
            except Exception as e:
                logger.error(f"Failed to update secret {key}: {e}")
                return False
        except Exception as e:
            logger.error(f"Failed to set secret {key}: {e}")
            return False
    
    async def delete_secret(self, key: str) -> bool:
        """Удалить секрет из AWS Secrets Manager"""
        try:
            client = self._get_client()
            secret_name = f"{self.prefix}{key}"
            client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {key}: {e}")
            return False

class SecretsManager:
    """Менеджер секретов с поддержкой разных провайдеров"""
    
    def __init__(self, provider: SecretsProvider):
        self.provider = provider
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = timedelta(minutes=5)
    
    async def get_secret(self, key: str, use_cache: bool = True) -> Optional[str]:
        """Получить секрет с кэшированием"""
        if use_cache and key in self._cache:
            cached = self._cache[key]
            if datetime.now() - cached['timestamp'] < self._cache_ttl:
                return cached['value']
        
        value = await self.provider.get_secret(key)
        
        if value is not None:
            self._cache[key] = {
                'value': value,
                'timestamp': datetime.now()
            }
        
        return value
    
    async def set_secret(self, key: str, value: str) -> bool:
        """Установить секрет"""
        success = await self.provider.set_secret(key, value)
        if success:
            # Обновляем кэш
            self._cache[key] = {
                'value': value,
                'timestamp': datetime.now()
            }
        return success
    
    async def delete_secret(self, key: str) -> bool:
        """Удалить секрет"""
        success = await self.provider.delete_secret(key)
        if success and key in self._cache:
            del self._cache[key]
        return success
    
    async def get_database_url(self) -> str:
        """Получить URL базы данных из секретов"""
        host = await self.get_secret("database_host") or "localhost"
        port = await self.get_secret("database_port") or "5432"
        name = await self.get_secret("database_name") or "samokoder"
        user = await self.get_secret("database_user") or "postgres"
        password = await self.get_secret("database_password") or "password"
        
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"
    
    async def get_supabase_config(self) -> Dict[str, str]:
        """Получить конфигурацию Supabase из секретов"""
        return {
            "url": await self.get_secret("supabase_url") or "",
            "anon_key": await self.get_secret("supabase_anon_key") or "",
            "service_role_key": await self.get_secret("supabase_service_role_key") or ""
        }
    
    async def get_ai_api_keys(self) -> Dict[str, str]:
        """Получить API ключи AI провайдеров из секретов"""
        return {
            "openrouter": await self.get_secret("openrouter_api_key") or "",
            "openai": await self.get_secret("openai_api_key") or "",
            "anthropic": await self.get_secret("anthropic_api_key") or "",
            "groq": await self.get_secret("groq_api_key") or ""
        }
    
    async def get_encryption_keys(self) -> Dict[str, str]:
        """Получить ключи шифрования из секретов"""
        return {
            "api_encryption_key": await self.get_secret("api_encryption_key") or "",
            "api_encryption_salt": await self.get_secret("api_encryption_salt") or "",
            "jwt_secret": await self.get_secret("jwt_secret") or "",
            "csrf_secret": await self.get_secret("csrf_secret") or ""
        }

def get_secrets_provider() -> SecretsProvider:
    """Получить провайдер секретов в зависимости от окружения"""
    environment = os.getenv("ENVIRONMENT", "development")
    
    if environment == "production":
        # В production используем AWS Secrets Manager
        return AWSSecretsManagerProvider()
    elif environment == "staging":
        # В staging используем файл секретов
        return FileSecretsProvider()
    else:
        # В development используем переменные окружения
        return EnvironmentSecretsProvider()

# Глобальный экземпляр
secrets_manager = SecretsManager(get_secrets_provider())