#!/usr/bin/env python3
"""
Дополнительные тесты для Key Rotation
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from backend.security.key_rotation import (
    KeyRotationManager, key_rotation_manager
)


class TestKeyRotationAdditional:
    """Дополнительные тесты для Key Rotation модуля"""
    
    def test_key_rotation_manager_init(self):
        """Тест инициализации менеджера ротации ключей"""
        manager = KeyRotationManager()
        
        assert manager is not None
        assert hasattr(manager, 'rotation_schedule')
        assert hasattr(manager, 'rotation_history')
        
        # Проверяем расписание ротации
        assert 'api_encryption_key' in manager.rotation_schedule
        assert 'jwt_secret' in manager.rotation_schedule
        assert 'csrf_secret' in manager.rotation_schedule
        assert 'openrouter_api_key' in manager.rotation_schedule
        
        # Проверяем периоды ротации
        assert manager.rotation_schedule['api_encryption_key'] == timedelta(days=90)
        assert manager.rotation_schedule['jwt_secret'] == timedelta(days=30)
        assert manager.rotation_schedule['csrf_secret'] == timedelta(days=60)
        assert manager.rotation_schedule['openrouter_api_key'] == timedelta(days=180)
    
    def test_generate_secure_key_encryption_type(self):
        """Тест генерации ключей шифрования"""
        manager = KeyRotationManager()
        
        # Тестируем генерацию ключей шифрования
        key = manager.generate_secure_key('api_encryption_key', 32)
        assert key is not None
        assert isinstance(key, str)
        assert len(key) > 0
        
        # Тестируем JWT секрет
        jwt_key = manager.generate_secure_key('jwt_secret', 32)
        assert jwt_key is not None
        assert isinstance(jwt_key, str)
        
        # Тестируем CSRF секрет
        csrf_key = manager.generate_secure_key('csrf_secret', 32)
        assert csrf_key is not None
        assert isinstance(csrf_key, str)
    
    def test_generate_secure_key_api_type(self):
        """Тест генерации API ключей"""
        manager = KeyRotationManager()
        
        # Тестируем генерацию API ключей
        api_key = manager.generate_secure_key('openrouter_api_key', 24)
        assert api_key is not None
        assert isinstance(api_key, str)
        assert len(api_key) > 0
        
        # Тестируем другие API ключи
        openai_key = manager.generate_secure_key('openai_api_key', 24)
        assert openai_key is not None
        assert isinstance(openai_key, str)
        
        anthropic_key = manager.generate_secure_key('anthropic_api_key', 24)
        assert anthropic_key is not None
        assert isinstance(anthropic_key, str)
    
    def test_generate_secure_key_different_lengths(self):
        """Тест генерации ключей разной длины"""
        manager = KeyRotationManager()
        
        # Тестируем разные длины
        short_key = manager.generate_secure_key('api_encryption_key', 16)
        assert short_key is not None
        
        long_key = manager.generate_secure_key('api_encryption_key', 64)
        assert long_key is not None
        
        # Ключи должны быть разными
        assert short_key != long_key
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_last_rotation_date_from_history(self, mock_secrets_manager):
        """Тест получения даты ротации из истории"""
        manager = KeyRotationManager()
        
        # Добавляем в историю
        test_date = datetime.now()
        manager.rotation_history['test_key'] = test_date
        
        result = await manager.get_last_rotation_date('test_key')
        
        assert result == test_date
        mock_secrets_manager.get_secret.assert_not_called()
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_last_rotation_date_from_secrets(self, mock_secrets_manager):
        """Тест получения даты ротации из секретов"""
        manager = KeyRotationManager()
        
        test_date = datetime.now()
        mock_secrets_manager.get_secret.return_value = test_date.isoformat()
        
        result = await manager.get_last_rotation_date('test_key')
        
        assert result == test_date
        mock_secrets_manager.get_secret.assert_called_once_with('test_key_last_rotation')
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_last_rotation_date_invalid_format(self, mock_secrets_manager):
        """Тест обработки неверного формата даты"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.get_secret.return_value = "invalid_date_format"
        
        result = await manager.get_last_rotation_date('test_key')
        
        assert result is None
        mock_secrets_manager.get_secret.assert_called_once_with('test_key_last_rotation')
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_last_rotation_date_not_found(self, mock_secrets_manager):
        """Тест когда дата ротации не найдена"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.get_secret.return_value = None
        
        result = await manager.get_last_rotation_date('test_key')
        
        assert result is None
        mock_secrets_manager.get_secret.assert_called_once_with('test_key_last_rotation')
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_rotate_key_success(self, mock_secrets_manager):
        """Тест успешной ротации ключа"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.set_secret = AsyncMock(return_value=True)
        
        result = await manager.rotate_key('test_key', 'admin')
        
        assert result is True
        assert 'test_key' in manager.rotation_history
        
        # Проверяем что секреты были сохранены
        assert mock_secrets_manager.set_secret.call_count == 2
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_rotate_key_failure(self, mock_secrets_manager):
        """Тест неудачной ротации ключа"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.set_secret = AsyncMock(return_value=False)
        
        result = await manager.rotate_key('test_key', 'admin')
        
        assert result is False
        assert 'test_key' not in manager.rotation_history
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_rotate_key_exception(self, mock_secrets_manager):
        """Тест исключения при ротации ключа"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.set_secret = AsyncMock(side_effect=Exception("Test error"))
        
        result = await manager.rotate_key('test_key', 'admin')
        
        assert result is False
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_rotate_all_expired_keys(self, mock_secrets_manager):
        """Тест ротации всех просроченных ключей"""
        manager = KeyRotationManager()
        
        # Мокаем check_rotation_needed
        with patch.object(manager, 'check_rotation_needed', return_value=['key1', 'key2']):
            with patch.object(manager, 'rotate_key', side_effect=[True, False]):
                results = await manager.rotate_all_expired_keys('system')
        
        assert results == {'key1': True, 'key2': False}
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_log_key_rotation_success(self, mock_secrets_manager):
        """Тест успешного логирования ротации"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.get_secret = AsyncMock(return_value="[]")
        mock_secrets_manager.set_secret = AsyncMock(return_value=True)
        
        test_date = datetime.now()
        await manager.log_key_rotation('test_key', 'admin', test_date)
        
        # Проверяем что секреты были вызваны
        mock_secrets_manager.get_secret.assert_called_once_with('key_rotation_log')
        mock_secrets_manager.set_secret.assert_called_once()
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_log_key_rotation_existing_logs(self, mock_secrets_manager):
        """Тест логирования с существующими логами"""
        manager = KeyRotationManager()
        
        existing_logs = '[{"event": "key_rotation", "key_name": "old_key"}]'
        mock_secrets_manager.get_secret = AsyncMock(return_value=existing_logs)
        mock_secrets_manager.set_secret = AsyncMock(return_value=True)
        
        test_date = datetime.now()
        await manager.log_key_rotation('test_key', 'admin', test_date)
        
        # Проверяем что секреты были вызваны
        mock_secrets_manager.get_secret.assert_called_once_with('key_rotation_log')
        mock_secrets_manager.set_secret.assert_called_once()
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_log_key_rotation_exception(self, mock_secrets_manager):
        """Тест исключения при логировании"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.get_secret = AsyncMock(side_effect=Exception("Test error"))
        
        test_date = datetime.now()
        # Не должно вызывать исключение
        await manager.log_key_rotation('test_key', 'admin', test_date)
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_rotation_status(self, mock_secrets_manager):
        """Тест получения статуса ротации"""
        manager = KeyRotationManager()
        
        # Мокаем get_last_rotation_date
        with patch.object(manager, 'get_last_rotation_date', return_value=None):
            status = await manager.get_rotation_status()
        
        assert 'api_encryption_key' in status
        assert 'jwt_secret' in status
        assert 'csrf_secret' in status
        
        # Проверяем структуру статуса
        key_status = status['api_encryption_key']
        assert 'last_rotation' in key_status
        assert 'next_rotation' in key_status
        assert 'days_until_rotation' in key_status
        assert 'rotation_period_days' in key_status
        assert 'needs_rotation' in key_status
        
        # Для ключа без ротации
        assert key_status['last_rotation'] is None
        assert key_status['next_rotation'] is None
        assert key_status['days_until_rotation'] is None
        assert key_status['needs_rotation'] is True
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_get_rotation_status_with_rotation(self, mock_secrets_manager):
        """Тест статуса ротации с существующей ротацией"""
        manager = KeyRotationManager()
        
        # Мокаем get_last_rotation_date с датой
        test_date = datetime.now() - timedelta(days=10)
        with patch.object(manager, 'get_last_rotation_date', return_value=test_date):
            status = await manager.get_rotation_status()
        
        key_status = status['jwt_secret']  # 30 дней период
        assert key_status['last_rotation'] == test_date.isoformat()
        assert key_status['next_rotation'] is not None
        assert key_status['days_until_rotation'] is not None
        assert key_status['rotation_period_days'] == 30
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_schedule_rotation_success(self, mock_secrets_manager):
        """Тест успешного планирования ротации"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.set_secret = AsyncMock(return_value=True)
        
        test_date = datetime.now() + timedelta(days=7)
        result = await manager.schedule_rotation('test_key', test_date)
        
        assert result is True
        mock_secrets_manager.set_secret.assert_called_once_with(
            'test_key_scheduled_rotation', 
            test_date.isoformat()
        )
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_schedule_rotation_failure(self, mock_secrets_manager):
        """Тест неудачного планирования ротации"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.set_secret = AsyncMock(side_effect=Exception("Test error"))
        
        test_date = datetime.now() + timedelta(days=7)
        result = await manager.schedule_rotation('test_key', test_date)
        
        assert result is False
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_cancel_scheduled_rotation_success(self, mock_secrets_manager):
        """Тест успешной отмены запланированной ротации"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.delete_secret = AsyncMock(return_value=True)
        
        result = await manager.cancel_scheduled_rotation('test_key')
        
        assert result is True
        mock_secrets_manager.delete_secret.assert_called_once_with('test_key_scheduled_rotation')
    
    @patch('backend.security.key_rotation.secrets_manager')
    async def test_cancel_scheduled_rotation_failure(self, mock_secrets_manager):
        """Тест неудачной отмены запланированной ротации"""
        manager = KeyRotationManager()
        
        mock_secrets_manager.delete_secret = AsyncMock(side_effect=Exception("Test error"))
        
        result = await manager.cancel_scheduled_rotation('test_key')
        
        assert result is False
    
    def test_global_instance_exists(self):
        """Тест существования глобального экземпляра"""
        assert key_rotation_manager is not None
        assert isinstance(key_rotation_manager, KeyRotationManager)
    
    def test_rotation_schedule_completeness(self):
        """Тест полноты расписания ротации"""
        manager = KeyRotationManager()
        
        expected_keys = [
            'api_encryption_key', 'jwt_secret', 'csrf_secret',
            'openrouter_api_key', 'openai_api_key', 'anthropic_api_key', 'groq_api_key'
        ]
        
        for key in expected_keys:
            assert key in manager.rotation_schedule
            assert isinstance(manager.rotation_schedule[key], timedelta)
    
    def test_rotation_periods_reasonable(self):
        """Тест разумности периодов ротации"""
        manager = KeyRotationManager()
        
        # JWT секрет должен ротироваться чаще (30 дней)
        assert manager.rotation_schedule['jwt_secret'].days == 30
        
        # CSRF секрет - средняя частота (60 дней)
        assert manager.rotation_schedule['csrf_secret'].days == 60
        
        # API ключи шифрования - реже (90 дней)
        assert manager.rotation_schedule['api_encryption_key'].days == 90
        
        # API ключи провайдеров - реже всего (180 дней)
        assert manager.rotation_schedule['openrouter_api_key'].days == 180
        assert manager.rotation_schedule['openai_api_key'].days == 180
        assert manager.rotation_schedule['anthropic_api_key'].days == 180
        assert manager.rotation_schedule['groq_api_key'].days == 180
    
    def test_key_generation_entropy(self):
        """Тест энтропии генерируемых ключей"""
        manager = KeyRotationManager()
        
        # Генерируем несколько ключей
        keys = []
        for _ in range(5):
            key = manager.generate_secure_key('api_encryption_key', 32)
            keys.append(key)
        
        # Все ключи должны быть разными
        assert len(set(keys)) == len(keys)
        
        # Ключи должны иметь достаточную длину
        for key in keys:
            assert len(key) >= 32  # Минимальная длина
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.security.key_rotation import (
            KeyRotationManager, key_rotation_manager
        )
        
        assert KeyRotationManager is not None
        assert key_rotation_manager is not None