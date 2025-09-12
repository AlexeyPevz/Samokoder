#!/usr/bin/env python3
"""
Дополнительные тесты для Secrets Manager
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, mock_open
from datetime import datetime, timedelta
import json
import os
from backend.security.secrets_manager import (
    SecretsProvider, EnvironmentSecretsProvider, FileSecretsProvider,
    AWSSecretsManagerProvider, SecretsManager, get_secrets_provider,
    secrets_manager
)


class TestSecretsManagerAdditional:
    """Дополнительные тесты для Secrets Manager модуля"""
    
    def test_secrets_provider_abstract(self):
        """Тест абстрактного класса SecretsProvider"""
        # Нельзя создать экземпляр абстрактного класса
        with pytest.raises(TypeError):
            SecretsProvider()
    
    def test_environment_secrets_provider_init(self):
        """Тест инициализации EnvironmentSecretsProvider"""
        provider = EnvironmentSecretsProvider()
        assert provider is not None
        assert provider.prefix == ""
        
        provider_with_prefix = EnvironmentSecretsProvider("TEST_")
        assert provider_with_prefix.prefix == "TEST_"
    
    @patch.dict(os.environ, {'TEST_SECRET': 'test_value'})
    async def test_environment_provider_get_secret(self):
        """Тест получения секрета из переменных окружения"""
        provider = EnvironmentSecretsProvider("TEST_")
        
        value = await provider.get_secret("secret")
        assert value == "test_value"
    
    async def test_environment_provider_get_secret_not_found(self):
        """Тест получения несуществующего секрета"""
        provider = EnvironmentSecretsProvider()
        
        value = await provider.get_secret("nonexistent")
        assert value is None
    
    @patch.dict(os.environ, {}, clear=True)
    async def test_environment_provider_set_secret(self):
        """Тест установки секрета в переменные окружения"""
        provider = EnvironmentSecretsProvider()
        
        result = await provider.set_secret("test_key", "test_value")
        assert result is True
        assert os.environ["TEST_KEY"] == "test_value"
    
    @patch.dict(os.environ, {'TEST_KEY': 'old_value'}, clear=True)
    async def test_environment_provider_delete_secret(self):
        """Тест удаления секрета из переменных окружения"""
        provider = EnvironmentSecretsProvider()
        
        result = await provider.delete_secret("test_key")
        assert result is True
        assert "TEST_KEY" not in os.environ
    
    @patch.dict(os.environ, {}, clear=True)
    async def test_environment_provider_delete_nonexistent_secret(self):
        """Тест удаления несуществующего секрета"""
        provider = EnvironmentSecretsProvider()
        
        result = await provider.delete_secret("nonexistent")
        assert result is True  # Удаление несуществующего секрета считается успешным
    
    def test_file_secrets_provider_init(self):
        """Тест инициализации FileSecretsProvider"""
        provider = FileSecretsProvider("test_secrets.json")
        assert provider is not None
        assert provider.secrets_file == "test_secrets.json"
        assert hasattr(provider, '_secrets')
    
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', mock_open(read_data='{"key1": "value1", "key2": "value2"}'))
    def test_file_provider_load_secrets(self, mock_exists):
        """Тест загрузки секретов из файла"""
        provider = FileSecretsProvider("test_secrets.json")
        
        assert provider._secrets == {"key1": "value1", "key2": "value2"}
    
    @patch('os.path.exists', return_value=False)
    def test_file_provider_load_secrets_no_file(self, mock_exists):
        """Тест загрузки секретов когда файл не существует"""
        provider = FileSecretsProvider("test_secrets.json")
        
        assert provider._secrets == {}
    
    @patch('builtins.open', side_effect=IOError("Permission denied"))
    @patch('os.path.exists', return_value=True)
    def test_file_provider_load_secrets_error(self, mock_exists, mock_open):
        """Тест ошибки при загрузке секретов"""
        provider = FileSecretsProvider("test_secrets.json")
        
        assert provider._secrets == {}
    
    async def test_file_provider_get_secret(self):
        """Тест получения секрета из файла"""
        provider = FileSecretsProvider("test_secrets.json")
        provider._secrets = {"test_key": "test_value"}
        
        value = await provider.get_secret("test_key")
        assert value == "test_value"
        
        value = await provider.get_secret("nonexistent")
        assert value is None
    
    @patch('builtins.open', mock_open())
    @patch('json.dump')
    async def test_file_provider_set_secret(self, mock_json_dump):
        """Тест установки секрета в файл"""
        provider = FileSecretsProvider("test_secrets.json")
        
        result = await provider.set_secret("test_key", "test_value")
        assert result is True
        assert provider._secrets["test_key"] == "test_value"
        mock_json_dump.assert_called_once()
    
    @patch('builtins.open', side_effect=IOError("Permission denied"))
    @patch('json.dump')
    async def test_file_provider_set_secret_error(self, mock_json_dump, mock_open):
        """Тест ошибки при установке секрета"""
        provider = FileSecretsProvider("test_secrets.json")
        
        result = await provider.set_secret("test_key", "test_value")
        assert result is True  # Секрет установлен в память, даже если файл не сохранен
        assert provider._secrets["test_key"] == "test_value"
    
    @patch('builtins.open', mock_open())
    @patch('json.dump')
    async def test_file_provider_delete_secret(self, mock_json_dump):
        """Тест удаления секрета из файла"""
        provider = FileSecretsProvider("test_secrets.json")
        provider._secrets = {"test_key": "test_value", "other_key": "other_value"}
        
        result = await provider.delete_secret("test_key")
        assert result is True
        assert "test_key" not in provider._secrets
        assert "other_key" in provider._secrets
        mock_json_dump.assert_called_once()
    
    async def test_file_provider_delete_nonexistent_secret(self):
        """Тест удаления несуществующего секрета"""
        provider = FileSecretsProvider("test_secrets.json")
        
        result = await provider.delete_secret("nonexistent")
        assert result is True
    
    def test_aws_secrets_manager_provider_init(self):
        """Тест инициализации AWSSecretsManagerProvider"""
        provider = AWSSecretsManagerProvider("us-west-2", "/app/")
        assert provider is not None
        assert provider.region == "us-west-2"
        assert provider.prefix == "/app/"
        assert provider._client is None
    
    
    @patch('backend.security.secrets_manager.boto3')
    async def test_aws_provider_get_secret_success(self, mock_boto3):
        """Тест успешного получения секрета из AWS"""
        mock_client = Mock()
        mock_client.get_secret_value.return_value = {'SecretString': 'secret_value'}
        mock_boto3.client.return_value = mock_client
        
        provider = AWSSecretsManagerProvider()
        
        value = await provider.get_secret("test_key")
        assert value == "secret_value"
        mock_client.get_secret_value.assert_called_once_with(SecretId="/samokoder/test_key")
    
    @patch('backend.security.secrets_manager.boto3')
    async def test_aws_provider_get_secret_error(self, mock_boto3):
        """Тест ошибки при получении секрета из AWS"""
        mock_client = Mock()
        mock_client.get_secret_value.side_effect = Exception("AWS Error")
        mock_boto3.client.return_value = mock_client
        
        provider = AWSSecretsManagerProvider()
        
        value = await provider.get_secret("test_key")
        assert value is None
    
    def test_secrets_manager_init(self):
        """Тест инициализации SecretsManager"""
        provider = EnvironmentSecretsProvider()
        manager = SecretsManager(provider)
        
        assert manager is not None
        assert manager.provider == provider
        assert hasattr(manager, '_cache')
        assert manager._cache_ttl == timedelta(minutes=5)
    
    async def test_secrets_manager_get_secret_cached(self):
        """Тест получения секрета из кэша"""
        provider = EnvironmentSecretsProvider()
        manager = SecretsManager(provider)
        
        # Добавляем в кэш
        manager._cache["test_key"] = {
            'value': 'cached_value',
            'timestamp': datetime.now()
        }
        
        value = await manager.get_secret("test_key")
        assert value == "cached_value"
    
    async def test_secrets_manager_get_secret_cache_expired(self):
        """Тест получения секрета с истекшим кэшем"""
        provider = EnvironmentSecretsProvider()
        provider.get_secret = AsyncMock(return_value="fresh_value")
        manager = SecretsManager(provider)
        
        # Добавляем истекший кэш
        manager._cache["test_key"] = {
            'value': 'cached_value',
            'timestamp': datetime.now() - timedelta(minutes=10)
        }
        
        value = await manager.get_secret("test_key")
        assert value == "fresh_value"
        provider.get_secret.assert_called_once_with("test_key")
    
    async def test_secrets_manager_get_secret_no_cache(self):
        """Тест получения секрета без кэша"""
        provider = EnvironmentSecretsProvider()
        provider.get_secret = AsyncMock(return_value="fresh_value")
        manager = SecretsManager(provider)
        
        value = await manager.get_secret("test_key", use_cache=False)
        assert value == "fresh_value"
        provider.get_secret.assert_called_once_with("test_key")
    
    async def test_secrets_manager_set_secret(self):
        """Тест установки секрета"""
        provider = EnvironmentSecretsProvider()
        provider.set_secret = AsyncMock(return_value=True)
        manager = SecretsManager(provider)
        
        result = await manager.set_secret("test_key", "test_value")
        assert result is True
        provider.set_secret.assert_called_once_with("test_key", "test_value")
        
        # Проверяем что секрет добавлен в кэш
        assert "test_key" in manager._cache
        assert manager._cache["test_key"]["value"] == "test_value"
    
    async def test_secrets_manager_delete_secret(self):
        """Тест удаления секрета"""
        provider = EnvironmentSecretsProvider()
        provider.delete_secret = AsyncMock(return_value=True)
        manager = SecretsManager(provider)
        
        # Добавляем в кэш
        manager._cache["test_key"] = {
            'value': 'test_value',
            'timestamp': datetime.now()
        }
        
        result = await manager.delete_secret("test_key")
        assert result is True
        provider.delete_secret.assert_called_once_with("test_key")
        
        # Проверяем что секрет удален из кэша
        assert "test_key" not in manager._cache
    
    async def test_secrets_manager_get_database_url(self):
        """Тест получения URL базы данных"""
        provider = EnvironmentSecretsProvider()
        provider.get_secret = AsyncMock(side_effect=lambda key: {
            "database_host": "localhost",
            "database_port": "5432",
            "database_name": "test_db",
            "database_user": "test_user",
            "database_password": "test_pass"
        }.get(key))
        
        manager = SecretsManager(provider)
        
        url = await manager.get_database_url()
        expected_url = "postgresql://test_user:test_pass@localhost:5432/test_db"
        assert url == expected_url
    
    async def test_secrets_manager_get_supabase_config(self):
        """Тест получения конфигурации Supabase"""
        provider = EnvironmentSecretsProvider()
        provider.get_secret = AsyncMock(side_effect=lambda key: {
            "supabase_url": "https://test.supabase.co",
            "supabase_anon_key": "anon_key_123",
            "supabase_service_role_key": "service_key_123"
        }.get(key))
        
        manager = SecretsManager(provider)
        
        config = await manager.get_supabase_config()
        expected_config = {
            "url": "https://test.supabase.co",
            "anon_key": "anon_key_123",
            "service_role_key": "service_key_123"
        }
        assert config == expected_config
    
    async def test_secrets_manager_get_ai_api_keys(self):
        """Тест получения API ключей AI провайдеров"""
        provider = EnvironmentSecretsProvider()
        provider.get_secret = AsyncMock(side_effect=lambda key: {
            "openrouter_api_key": "openrouter_123",
            "openai_api_key": "openai_123",
            "anthropic_api_key": "anthropic_123",
            "groq_api_key": "groq_123"
        }.get(key))
        
        manager = SecretsManager(provider)
        
        keys = await manager.get_ai_api_keys()
        expected_keys = {
            "openrouter": "openrouter_123",
            "openai": "openai_123",
            "anthropic": "anthropic_123",
            "groq": "groq_123"
        }
        assert keys == expected_keys
    
    async def test_secrets_manager_get_encryption_keys(self):
        """Тест получения ключей шифрования"""
        provider = EnvironmentSecretsProvider()
        provider.get_secret = AsyncMock(side_effect=lambda key: {
            "api_encryption_key": "enc_key_123",
            "api_encryption_salt": "salt_123",
            "jwt_secret": "jwt_123",
            "csrf_secret": "csrf_123"
        }.get(key))
        
        manager = SecretsManager(provider)
        
        keys = await manager.get_encryption_keys()
        expected_keys = {
            "api_encryption_key": "enc_key_123",
            "api_encryption_salt": "salt_123",
            "jwt_secret": "jwt_123",
            "csrf_secret": "csrf_123"
        }
        assert keys == expected_keys
    
    @patch.dict(os.environ, {'ENVIRONMENT': 'production'})
    def test_get_secrets_provider_production(self):
        """Тест получения провайдера для production"""
        provider = get_secrets_provider()
        assert isinstance(provider, AWSSecretsManagerProvider)
    
    @patch.dict(os.environ, {'ENVIRONMENT': 'staging'})
    def test_get_secrets_provider_staging(self):
        """Тест получения провайдера для staging"""
        provider = get_secrets_provider()
        assert isinstance(provider, FileSecretsProvider)
    
    @patch.dict(os.environ, {'ENVIRONMENT': 'development'})
    def test_get_secrets_provider_development(self):
        """Тест получения провайдера для development"""
        provider = get_secrets_provider()
        assert isinstance(provider, EnvironmentSecretsProvider)
    
    @patch.dict(os.environ, {}, clear=True)
    def test_get_secrets_provider_default(self):
        """Тест получения провайдера по умолчанию"""
        provider = get_secrets_provider()
        assert isinstance(provider, EnvironmentSecretsProvider)
    
    def test_global_instance_exists(self):
        """Тест существования глобального экземпляра"""
        assert secrets_manager is not None
        assert isinstance(secrets_manager, SecretsManager)
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.security.secrets_manager import (
            SecretsProvider, EnvironmentSecretsProvider, FileSecretsProvider,
            AWSSecretsManagerProvider, SecretsManager, get_secrets_provider,
            secrets_manager
        )
        
        assert SecretsProvider is not None
        assert EnvironmentSecretsProvider is not None
        assert FileSecretsProvider is not None
        assert AWSSecretsManagerProvider is not None
        assert SecretsManager is not None
        assert get_secrets_provider is not None
        assert secrets_manager is not None