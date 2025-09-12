"""
Комплексные тесты для KeyRotationManager (21% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from backend.security.key_rotation import KeyRotationManager
from backend.core.exceptions import EncryptionError


class TestKeyRotationManager:
    """Тесты для KeyRotationManager"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.manager = KeyRotationManager()

    def test_init(self):
        """Тест инициализации KeyRotationManager"""
        manager = KeyRotationManager()
        assert hasattr(manager, 'rotation_schedule')
        assert hasattr(manager, 'rotation_history')
        assert 'api_encryption_key' in manager.rotation_schedule
        assert 'jwt_secret' in manager.rotation_schedule
        assert manager.rotation_schedule['api_encryption_key'] == timedelta(days=90)
        assert manager.rotation_schedule['jwt_secret'] == timedelta(days=30)

    def test_generate_secure_key_encryption_key(self):
        """Тест генерации ключа шифрования"""
        key = self.manager.generate_secure_key('api_encryption_key', length=32)
        
        assert isinstance(key, str)
        assert len(key) > 0
        # base64.urlsafe_b64encode(32 bytes) = 44 chars
        assert len(key) >= 40

    def test_generate_secure_key_jwt_secret(self):
        """Тест генерации JWT секрета"""
        key = self.manager.generate_secure_key('jwt_secret', length=64)
        
        assert isinstance(key, str)
        assert len(key) > 0
        # base64.urlsafe_b64encode(64 bytes) = 88 chars
        assert len(key) >= 80

    def test_generate_secure_key_csrf_secret(self):
        """Тест генерации CSRF секрета"""
        key = self.manager.generate_secure_key('csrf_secret', length=32)
        
        assert isinstance(key, str)
        assert len(key) > 0
        assert len(key) >= 40

    def test_generate_secure_key_api_key(self):
        """Тест генерации API ключа"""
        key = self.manager.generate_secure_key('openrouter_api_key', length=32)
        
        assert isinstance(key, str)
        assert len(key) > 0
        # secrets.token_hex(32) = 64 hex chars
        assert len(key) == 64

    def test_generate_secure_key_different_lengths(self):
        """Тест генерации ключей разной длины"""
        # Тест разных длин для ключей шифрования
        for length in [16, 32, 64, 128]:
            key = self.manager.generate_secure_key('api_encryption_key', length=length)
            assert isinstance(key, str)
            assert len(key) > 0
        
        # Тест разных длин для API ключей
        for length in [16, 32, 64]:
            key = self.manager.generate_secure_key('openai_api_key', length=length)
            assert isinstance(key, str)
            assert len(key) == length * 2  # hex encoding doubles length

    def test_generate_secure_key_uniqueness(self):
        """Тест уникальности генерируемых ключей"""
        keys = set()
        for _ in range(100):
            key = self.manager.generate_secure_key('api_encryption_key')
            keys.add(key)
        
        # Все ключи должны быть уникальными
        assert len(keys) == 100

    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_last_rotation_date_exists(self, mock_secrets_manager):
        """Тест получения даты последней ротации - ключ существует"""
        # Arrange
        key_name = 'api_encryption_key'
        last_rotation = datetime.now() - timedelta(days=30)
        mock_secrets_manager.get_secret.return_value = last_rotation.isoformat()
        
        # Act
        result = await self.manager.get_last_rotation_date(key_name)
        
        # Assert
        assert result == last_rotation
        mock_secrets_manager.get_secret.assert_called_once_with(f"last_rotation_{key_name}")

    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_last_rotation_date_not_exists(self, mock_secrets_manager):
        """Тест получения даты последней ротации - ключ не существует"""
        # Arrange
        key_name = 'new_key'
        mock_secrets_manager.get_secret.return_value = None
        
        # Act
        result = await self.manager.get_last_rotation_date(key_name)
        
        # Assert
        assert result is None
        mock_secrets_manager.get_secret.assert_called_once_with(f"last_rotation_{key_name}")

    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_last_rotation_date_invalid_format(self, mock_secrets_manager):
        """Тест получения даты последней ротации - неверный формат"""
        # Arrange
        key_name = 'api_encryption_key'
        mock_secrets_manager.get_secret.return_value = "invalid_date_format"
        
        # Act
        result = await self.manager.get_last_rotation_date(key_name)
        
        # Assert
        assert result is None
        mock_secrets_manager.get_secret.assert_called_once_with(f"last_rotation_{key_name}")

    @patch('backend.security.key_rotation.secrets_manager')
    async def test_set_last_rotation_date_success(self, mock_secrets_manager):
        """Тест установки даты последней ротации"""
        # Arrange
        key_name = 'api_encryption_key'
        rotation_date = datetime.now()
        mock_secrets_manager.set_secret.return_value = True
        
        # Act
        result = await self.manager.set_last_rotation_date(key_name, rotation_date)
        
        # Assert
        assert result is True
        mock_secrets_manager.set_secret.assert_called_once_with(
            f"last_rotation_{key_name}",
            rotation_date.isoformat()
        )

    @patch('backend.security.key_rotation.secrets_manager')
    async def test_set_last_rotation_date_failure(self, mock_secrets_manager):
        """Тест неудачной установки даты последней ротации"""
        # Arrange
        key_name = 'api_encryption_key'
        rotation_date = datetime.now()
        mock_secrets_manager.set_secret.return_value = False
        
        # Act
        result = await self.manager.set_last_rotation_date(key_name, rotation_date)
        
        # Assert
        assert result is False

    @patch('backend.security.key_rotation.KeyRotationManager.get_last_rotation_date')
    async def test_check_rotation_needed_new_keys(self, mock_get_last_rotation):
        """Тест проверки необходимости ротации - новые ключи"""
        # Arrange
        mock_get_last_rotation.return_value = None
        
        # Act
        result = await self.manager.check_rotation_needed()
        
        # Assert
        assert len(result) == len(self.manager.rotation_schedule)
        assert 'api_encryption_key' in result
        assert 'jwt_secret' in result
        assert 'csrf_secret' in result

    @patch('backend.security.key_rotation.KeyRotationManager.get_last_rotation_date')
    async def test_check_rotation_needed_recent_rotation(self, mock_get_last_rotation):
        """Тест проверки необходимости ротации - недавняя ротация"""
        # Arrange
        # Все ключи ротировались недавно
        recent_date = datetime.now() - timedelta(days=1)
        mock_get_last_rotation.return_value = recent_date
        
        # Act
        result = await self.manager.check_rotation_needed()
        
        # Assert
        assert result == []

    @patch('backend.security.key_rotation.KeyRotationManager.get_last_rotation_date')
    async def test_check_rotation_needed_old_rotation(self, mock_get_last_rotation):
        """Тест проверки необходимости ротации - старая ротация"""
        # Arrange
        # JWT секрет ротировался давно (больше 30 дней)
        old_date = datetime.now() - timedelta(days=35)
        
        def side_effect(key_name):
            if key_name == 'jwt_secret':
                return old_date
            else:
                return datetime.now() - timedelta(days=1)  # Недавно
        
        mock_get_last_rotation.side_effect = side_effect
        
        # Act
        result = await self.manager.check_rotation_needed()
        
        # Assert
        assert len(result) == 1
        assert 'jwt_secret' in result

    @patch('backend.security.key_rotation.KeyRotationManager.get_last_rotation_date')
    async def test_check_rotation_needed_mixed_ages(self, mock_get_last_rotation):
        """Тест проверки необходимости ротации - смешанные возрасты"""
        # Arrange
        def side_effect(key_name):
            if key_name == 'jwt_secret':
                return datetime.now() - timedelta(days=35)  # Старый
            elif key_name == 'api_encryption_key':
                return datetime.now() - timedelta(days=100)  # Старый
            else:
                return datetime.now() - timedelta(days=1)  # Недавно
        
        mock_get_last_rotation.side_effect = side_effect
        
        # Act
        result = await self.manager.check_rotation_needed()
        
        # Assert
        assert len(result) == 2
        assert 'jwt_secret' in result
        assert 'api_encryption_key' in result

    @patch('backend.security.key_rotation.KeyRotationManager.generate_secure_key')
    @patch('backend.security.key_rotation.secrets_manager')
    @patch('backend.security.key_rotation.KeyRotationManager.set_last_rotation_date')
    async def test_rotate_key_success(self, mock_set_date, mock_secrets_manager, mock_generate):
        """Тест успешной ротации ключа"""
        # Arrange
        key_name = 'jwt_secret'
        new_key = 'new_secure_key_123'
        mock_generate.return_value = new_key
        mock_secrets_manager.set_secret.return_value = True
        mock_set_date.return_value = True
        
        # Act
        result = await self.manager.rotate_key(key_name)
        
        # Assert
        assert result is True
        mock_generate.assert_called_once_with(key_name)
        mock_secrets_manager.set_secret.assert_called_once_with(key_name, new_key)
        mock_set_date.assert_called_once()

    @patch('backend.security.key_rotation.KeyRotationManager.generate_secure_key')
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_rotate_key_secrets_manager_failure(self, mock_secrets_manager, mock_generate):
        """Тест неудачной ротации ключа - ошибка secrets_manager"""
        # Arrange
        key_name = 'jwt_secret'
        new_key = 'new_secure_key_123'
        mock_generate.return_value = new_key
        mock_secrets_manager.set_secret.return_value = False
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.rotate_key(key_name)
        assert "Failed to rotate key" in str(exc_info.value)

    @patch('backend.security.key_rotation.KeyRotationManager.generate_secure_key')
    @patch('backend.security.key_rotation.secrets_manager')
    @patch('backend.security.key_rotation.KeyRotationManager.set_last_rotation_date')
    async def test_rotate_key_set_date_failure(self, mock_set_date, mock_secrets_manager, mock_generate):
        """Тест неудачной ротации ключа - ошибка установки даты"""
        # Arrange
        key_name = 'jwt_secret'
        new_key = 'new_secure_key_123'
        mock_generate.return_value = new_key
        mock_secrets_manager.set_secret.return_value = True
        mock_set_date.return_value = False
        
        # Act & Assert
        with pytest.raises(EncryptionError) as exc_info:
            await self.manager.rotate_key(key_name)
        assert "Failed to update rotation date" in str(exc_info.value)

    @patch('backend.security.key_rotation.KeyRotationManager.check_rotation_needed')
    @patch('backend.security.key_rotation.KeyRotationManager.rotate_key')
    async def test_rotate_expired_keys_success(self, mock_rotate_key, mock_check_rotation):
        """Тест успешной ротации просроченных ключей"""
        # Arrange
        keys_to_rotate = ['jwt_secret', 'api_encryption_key']
        mock_check_rotation.return_value = keys_to_rotate
        mock_rotate_key.return_value = True
        
        # Act
        result = await self.manager.rotate_expired_keys()
        
        # Assert
        assert result == {'rotated': keys_to_rotate, 'failed': []}
        assert mock_rotate_key.call_count == 2
        mock_rotate_key.assert_any_call('jwt_secret')
        mock_rotate_key.assert_any_call('api_encryption_key')

    @patch('backend.security.key_rotation.KeyRotationManager.check_rotation_needed')
    async def test_rotate_expired_keys_no_keys_to_rotate(self, mock_check_rotation):
        """Тест ротации просроченных ключей - нет ключей для ротации"""
        # Arrange
        mock_check_rotation.return_value = []
        
        # Act
        result = await self.manager.rotate_expired_keys()
        
        # Assert
        assert result == {'rotated': [], 'failed': []}

    @patch('backend.security.key_rotation.KeyRotationManager.check_rotation_needed')
    @patch('backend.security.key_rotation.KeyRotationManager.rotate_key')
    async def test_rotate_expired_keys_partial_failure(self, mock_rotate_key, mock_check_rotation):
        """Тест ротации просроченных ключей - частичная неудача"""
        # Arrange
        keys_to_rotate = ['jwt_secret', 'api_encryption_key', 'csrf_secret']
        mock_check_rotation.return_value = keys_to_rotate
        
        def side_effect(key_name):
            if key_name == 'api_encryption_key':
                raise EncryptionError("Rotation failed")
            return True
        
        mock_rotate_key.side_effect = side_effect
        
        # Act
        result = await self.manager.rotate_expired_keys()
        
        # Assert
        assert 'jwt_secret' in result['rotated']
        assert 'csrf_secret' in result['rotated']
        assert 'api_encryption_key' in result['failed']
        assert len(result['rotated']) == 2
        assert len(result['failed']) == 1

    @patch('backend.security.key_rotation.KeyRotationManager.check_rotation_needed')
    @patch('backend.security.key_rotation.KeyRotationManager.rotate_key')
    async def test_rotate_expired_keys_all_fail(self, mock_rotate_key, mock_check_rotation):
        """Тест ротации просроченных ключей - все неудачи"""
        # Arrange
        keys_to_rotate = ['jwt_secret', 'api_encryption_key']
        mock_check_rotation.return_value = keys_to_rotate
        mock_rotate_key.side_effect = EncryptionError("Rotation failed")
        
        # Act
        result = await self.manager.rotate_expired_keys()
        
        # Assert
        assert result['rotated'] == []
        assert result['failed'] == keys_to_rotate
