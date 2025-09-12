"""
Комплексные тесты для SecretsManager (33% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import os
import json
from backend.security.secrets_manager import (
    SecretsProvider,
    EnvironmentSecretsProvider,
    FileSecretsProvider,
    SecretsManager
)
from backend.core.exceptions import EncryptionError


class TestSecretsProvider:
    """Тесты для абстрактного класса SecretsProvider"""

    def test_secrets_provider_abstract(self):
        """Тест что SecretsProvider является абстрактным"""
        with pytest.raises(TypeError):
            SecretsProvider()


class TestEnvironmentSecretsProvider:
    """Тесты для EnvironmentSecretsProvider"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.provider = EnvironmentSecretsProvider()

    def test_init_default(self):
        """Тест инициализации с параметрами по умолчанию"""
        provider = EnvironmentSecretsProvider()
        assert provider.prefix == ""

    def test_init_with_prefix(self):
        """Тест инициализации с префиксом"""
        provider = EnvironmentSecretsProvider("MY_APP_")
        assert provider.prefix == "MY_APP_"

    @patch.dict(os.environ, {'TEST_KEY': 'test_value'}, clear=True)
    async def test_get_secret_exists(self):
        """Тест получения существующего секрета"""
        result = await self.provider.get_secret('test_key')
        assert result == 'test_value'

    @patch.dict(os.environ, {}, clear=True)
    async def test_get_secret_not_exists(self):
        """Тест получения несуществующего секрета"""
        result = await self.provider.get_secret('nonexistent_key')
        assert result is None

    @patch.dict(os.environ, {'MY_APP_API_KEY': 'api_value'}, clear=True)
    async def test_get_secret_with_prefix(self):
        """Тест получения секрета с префиксом"""
        provider = EnvironmentSecretsProvider("MY_APP_")
        result = await provider.get_secret('api_key')
        assert result == 'api_value'

    @patch.dict(os.environ, {}, clear=True)
    async def test_set_secret(self):
        """Тест установки секрета"""
        result = await self.provider.set_secret('new_key', 'new_value')
        assert result is True
        assert os.environ.get('NEW_KEY') == 'new_value'

    @patch.dict(os.environ, {}, clear=True)
    async def test_set_secret_with_prefix(self):
        """Тест установки секрета с префиксом"""
        provider = EnvironmentSecretsProvider("MY_APP_")
        result = await provider.set_secret('new_key', 'new_value')
        assert result is True
        assert os.environ.get('MY_APP_NEW_KEY') == 'new_value'

    @patch.dict(os.environ, {'EXISTING_KEY': 'existing_value'}, clear=True)
    async def test_delete_secret_exists(self):
        """Тест удаления существующего секрета"""
        result = await self.provider.delete_secret('existing_key')
        assert result is True
        assert 'EXISTING_KEY' not in os.environ

    @patch.dict(os.environ, {}, clear=True)
    async def test_delete_secret_not_exists(self):
        """Тест удаления несуществующего секрета"""
        result = await self.provider.delete_secret('nonexistent_key')
        assert result is True  # EnvironmentSecretsProvider всегда возвращает True

    @patch.dict(os.environ, {}, clear=True)
    async def test_delete_secret_with_prefix(self):
        """Тест удаления секрета с префиксом"""
        provider = EnvironmentSecretsProvider("MY_APP_")
        os.environ['MY_APP_TEST_KEY'] = 'test_value'
        result = await provider.delete_secret('test_key')
        assert result is True
        assert 'MY_APP_TEST_KEY' not in os.environ


class TestFileSecretsProvider:
    """Тесты для FileSecretsProvider"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.test_file = "/tmp/test_secrets.json"
        self.provider = FileSecretsProvider(self.test_file)

    def teardown_method(self):
        """Очистка после каждого теста"""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_init(self):
        """Тест инициализации FileSecretsProvider"""
        provider = FileSecretsProvider("/tmp/test.json")
        assert provider.secrets_file == "/tmp/test.json"
        assert provider._secrets == {}

    @patch('builtins.open', create=True)
    @patch('json.load')
    async def test_load_secrets_file_exists(self, mock_json_load, mock_open):
        """Тест загрузки секретов - файл существует"""
        # Arrange
        mock_secrets = {"key1": "value1", "key2": "value2"}
        mock_json_load.return_value = mock_secrets
        mock_open.return_value.__enter__.return_value = Mock()
        
        # Act
        self.provider._load_secrets()
        
        # Assert
        assert self.provider._secrets == mock_secrets
        mock_open.assert_called_once_with(self.test_file, 'r')
        mock_json_load.assert_called_once()

    @patch('os.path.exists')
    def test_load_secrets_file_not_exists(self, mock_exists):
        """Тест загрузки секретов - файл не существует"""
        # Arrange
        mock_exists.return_value = False
        
        # Act - создаем новый provider
        provider = FileSecretsProvider(self.test_file)
        
        # Assert
        assert provider._secrets == {}
        mock_exists.assert_called_once_with(self.test_file)

    @patch('builtins.open', create=True)
    @patch('json.dump')
    def test_save_secrets(self, mock_json_dump, mock_open):
        """Тест сохранения секретов"""
        # Arrange
        self.provider._secrets = {"key1": "value1", "key2": "value2"}
        mock_open.return_value.__enter__.return_value = Mock()
        
        # Act
        self.provider._save_secrets()
        
        # Assert
        mock_open.assert_called_once_with(self.test_file, 'w')
        mock_json_dump.assert_called_once_with({"key1": "value1", "key2": "value2"}, mock_open.return_value.__enter__.return_value, indent=2)

    async def test_get_secret_exists(self):
        """Тест получения существующего секрета"""
        # Arrange
        self.provider._secrets = {"test_key": "test_value"}
        
        # Act
        result = await self.provider.get_secret('test_key')
        
        # Assert
        assert result == "test_value"

    async def test_get_secret_not_exists(self):
        """Тест получения несуществующего секрета"""
        # Arrange
        self.provider._secrets = {"other_key": "other_value"}
        
        # Act
        result = await self.provider.get_secret('nonexistent_key')
        
        # Assert
        assert result is None

    @patch('backend.security.secrets_manager.FileSecretsProvider._save_secrets')
    async def test_set_secret(self, mock_save_secrets):
        """Тест установки секрета"""
        # Act
        result = await self.provider.set_secret('new_key', 'new_value')
        
        # Assert
        assert result is True
        assert self.provider._secrets['new_key'] == 'new_value'
        mock_save_secrets.assert_called_once()

    @patch('backend.security.secrets_manager.FileSecretsProvider._save_secrets')
    async def test_delete_secret_exists(self, mock_save_secrets):
        """Тест удаления существующего секрета"""
        # Arrange
        self.provider._secrets = {"test_key": "test_value"}
        
        # Act
        result = await self.provider.delete_secret('test_key')
        
        # Assert
        assert result is True
        assert 'test_key' not in self.provider._secrets
        mock_save_secrets.assert_called_once()

    @patch('backend.security.secrets_manager.FileSecretsProvider._save_secrets')
    async def test_delete_secret_not_exists(self, mock_save_secrets):
        """Тест удаления несуществующего секрета"""
        # Act
        result = await self.provider.delete_secret('nonexistent_key')
        
        # Assert
        assert result is True
        mock_save_secrets.assert_called_once()

    @patch('backend.security.secrets_manager.FileSecretsProvider._save_secrets', side_effect=Exception("Save failed"))
    async def test_set_secret_save_error(self, mock_save_secrets):
        """Тест ошибки сохранения при установке секрета"""
        # Act
        result = await self.provider.set_secret('new_key', 'new_value')
        
        # Assert
        assert result is False

    @patch('backend.security.secrets_manager.FileSecretsProvider._save_secrets', side_effect=Exception("Save failed"))
    async def test_delete_secret_save_error(self, mock_save_secrets):
        """Тест ошибки сохранения при удалении секрета"""
        # Arrange
        self.provider._secrets = {"test_key": "test_value"}
        
        # Act
        result = await self.provider.delete_secret('test_key')
        
        # Assert
        assert result is False




class TestSecretsManager:
    """Тесты для SecretsManager"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.mock_provider = Mock(spec=SecretsProvider)
        self.manager = SecretsManager(self.mock_provider)

    def test_init(self):
        """Тест инициализации SecretsManager"""
        manager = SecretsManager(self.mock_provider)
        assert manager.provider == self.mock_provider

    async def test_get_secret_success(self):
        """Тест успешного получения секрета"""
        # Arrange
        self.mock_provider.get_secret.return_value = "secret_value"
        
        # Act
        result = await self.manager.get_secret('test_key')
        
        # Assert
        assert result == "secret_value"
        self.mock_provider.get_secret.assert_called_once_with('test_key')

    async def test_get_secret_not_found(self):
        """Тест получения несуществующего секрета"""
        # Arrange
        self.mock_provider.get_secret.return_value = None
        
        # Act
        result = await self.manager.get_secret('nonexistent_key')
        
        # Assert
        assert result is None
        self.mock_provider.get_secret.assert_called_once_with('nonexistent_key')

    async def test_get_secret_provider_error(self):
        """Тест ошибки провайдера при получении секрета"""
        # Arrange
        self.mock_provider.get_secret.side_effect = Exception("Provider error")
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.get_secret('test_key')
        assert "Failed to get secret" in str(exc_info.value)

    async def test_set_secret_success(self):
        """Тест успешной установки секрета"""
        # Arrange
        self.mock_provider.set_secret.return_value = True
        
        # Act
        result = await self.manager.set_secret('test_key', 'test_value')
        
        # Assert
        assert result is True
        self.mock_provider.set_secret.assert_called_once_with('test_key', 'test_value')

    async def test_set_secret_provider_failure(self):
        """Тест неудачи провайдера при установке секрета"""
        # Arrange
        self.mock_provider.set_secret.return_value = False
        
        # Act
        result = await self.manager.set_secret('test_key', 'test_value')
        
        # Assert
        assert result is False
        self.mock_provider.set_secret.assert_called_once_with('test_key', 'test_value')

    async def test_set_secret_provider_error(self):
        """Тест ошибки провайдера при установке секрета"""
        # Arrange
        self.mock_provider.set_secret.side_effect = Exception("Provider error")
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.set_secret('test_key', 'test_value')
        assert "Failed to set secret" in str(exc_info.value)

    async def test_delete_secret_success(self):
        """Тест успешного удаления секрета"""
        # Arrange
        self.mock_provider.delete_secret.return_value = True
        
        # Act
        result = await self.manager.delete_secret('test_key')
        
        # Assert
        assert result is True
        self.mock_provider.delete_secret.assert_called_once_with('test_key')

    async def test_delete_secret_provider_failure(self):
        """Тест неудачи провайдера при удалении секрета"""
        # Arrange
        self.mock_provider.delete_secret.return_value = False
        
        # Act
        result = await self.manager.delete_secret('test_key')
        
        # Assert
        assert result is False
        self.mock_provider.delete_secret.assert_called_once_with('test_key')

    async def test_delete_secret_provider_error(self):
        """Тест ошибки провайдера при удалении секрета"""
        # Arrange
        self.mock_provider.delete_secret.side_effect = Exception("Provider error")
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.delete_secret('test_key')
        assert "Failed to delete secret" in str(exc_info.value)

    async def test_exists_success_true(self):
        """Тест проверки существования секрета - существует"""
        # Arrange
        self.mock_provider.get_secret.return_value = "secret_value"
        
        # Act
        result = await self.manager.exists('test_key')
        
        # Assert
        assert result is True
        self.mock_provider.get_secret.assert_called_once_with('test_key')

    async def test_exists_success_false(self):
        """Тест проверки существования секрета - не существует"""
        # Arrange
        self.mock_provider.get_secret.return_value = None
        
        # Act
        result = await self.manager.exists('nonexistent_key')
        
        # Assert
        assert result is False
        self.mock_provider.get_secret.assert_called_once_with('nonexistent_key')

    async def test_exists_provider_error(self):
        """Тест ошибки провайдера при проверке существования секрета"""
        # Arrange
        self.mock_provider.get_secret.side_effect = Exception("Provider error")
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.exists('test_key')
        assert "Failed to check secret existence" in str(exc_info.value)

    async def test_get_or_create_secret_exists(self):
        """Тест получения или создания секрета - существует"""
        # Arrange
        self.mock_provider.get_secret.return_value = "existing_value"
        
        # Act
        result = await self.manager.get_or_create_secret('test_key', 'default_value')
        
        # Assert
        assert result == "existing_value"
        self.mock_provider.get_secret.assert_called_once_with('test_key')
        self.mock_provider.set_secret.assert_not_called()

    async def test_get_or_create_secret_not_exists(self):
        """Тест получения или создания секрета - не существует"""
        # Arrange
        self.mock_provider.get_secret.return_value = None
        self.mock_provider.set_secret.return_value = True
        
        # Act
        result = await self.manager.get_or_create_secret('test_key', 'default_value')
        
        # Assert
        assert result == "default_value"
        self.mock_provider.get_secret.assert_called_once_with('test_key')
        self.mock_provider.set_secret.assert_called_once_with('test_key', 'default_value')

    async def test_get_or_create_secret_create_failure(self):
        """Тест получения или создания секрета - неудача создания"""
        # Arrange
        self.mock_provider.get_secret.return_value = None
        self.mock_provider.set_secret.return_value = False
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.get_or_create_secret('test_key', 'default_value')
        assert "Failed to create secret" in str(exc_info.value)

    async def test_batch_get_secrets_success(self):
        """Тест пакетного получения секретов"""
        # Arrange
        keys = ['key1', 'key2', 'key3']
        values = ['value1', None, 'value3']
        
        def side_effect(key):
            return values[keys.index(key)]
        
        self.mock_provider.get_secret.side_effect = side_effect
        
        # Act
        result = await self.manager.batch_get_secrets(keys)
        
        # Assert
        expected = {'key1': 'value1', 'key2': None, 'key3': 'value3'}
        assert result == expected
        assert self.mock_provider.get_secret.call_count == 3

    async def test_batch_get_secrets_provider_error(self):
        """Тест ошибки провайдера при пакетном получении секретов"""
        # Arrange
        keys = ['key1', 'key2']
        self.mock_provider.get_secret.side_effect = Exception("Provider error")
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.batch_get_secrets(keys)
        assert "Failed to batch get secrets" in str(exc_info.value)

    async def test_batch_set_secrets_success(self):
        """Тест пакетной установки секретов"""
        # Arrange
        secrets = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
        self.mock_provider.set_secret.return_value = True
        
        # Act
        result = await self.manager.batch_set_secrets(secrets)
        
        # Assert
        assert result == {'success': ['key1', 'key2', 'key3'], 'failed': []}
        assert self.mock_provider.set_secret.call_count == 3

    async def test_batch_set_secrets_partial_failure(self):
        """Тест частичной неудачи при пакетной установке секретов"""
        # Arrange
        secrets = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
        
        def side_effect(key, value):
            return key != 'key2'  # key2 fails
        
        self.mock_provider.set_secret.side_effect = side_effect
        
        # Act
        result = await self.manager.batch_set_secrets(secrets)
        
        # Assert
        assert result == {'success': ['key1', 'key3'], 'failed': ['key2']}
        assert self.mock_provider.set_secret.call_count == 3

    async def test_batch_set_secrets_all_failure(self):
        """Тест полной неудачи при пакетной установке секретов"""
        # Arrange
        secrets = {'key1': 'value1', 'key2': 'value2'}
        self.mock_provider.set_secret.return_value = False
        
        # Act
        result = await self.manager.batch_set_secrets(secrets)
        
        # Assert
        assert result == {'success': [], 'failed': ['key1', 'key2']}
        assert self.mock_provider.set_secret.call_count == 2

    async def test_batch_set_secrets_provider_error(self):
        """Тест ошибки провайдера при пакетной установке секретов"""
        # Arrange
        secrets = {'key1': 'value1', 'key2': 'value2'}
        self.mock_provider.set_secret.side_effect = Exception("Provider error")
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.batch_set_secrets(secrets)
        assert "Failed to batch set secrets" in str(exc_info.value)