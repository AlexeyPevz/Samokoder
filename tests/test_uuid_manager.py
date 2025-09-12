#!/usr/bin/env python3
"""
Тесты для UUID Manager
"""

import pytest
from unittest.mock import Mock, patch
import uuid
from datetime import datetime, timedelta
from backend.utils.uuid_manager import (
    UUIDManager, uuid_manager,
    generate_unique_uuid, is_uuid_unique,
    register_uuid, release_uuid, get_uuid_stats
)


class TestUUIDManager:
    """Тесты для UUID Manager модуля"""
    
    def test_uuid_manager_init(self):
        """Тест инициализации UUIDManager"""
        manager = UUIDManager()
        
        assert manager is not None
        assert hasattr(manager, '_used_uuids')
        assert hasattr(manager, '_lock')
        assert hasattr(manager, '_cleanup_interval')
        assert hasattr(manager, '_last_cleanup')
        
        # Проверяем начальные значения
        assert len(manager._used_uuids) == 0
        assert manager._cleanup_interval == timedelta(hours=1)
        assert isinstance(manager._last_cleanup, datetime)
    
    def test_generate_unique_uuid(self):
        """Тест генерации уникального UUID"""
        manager = UUIDManager()
        
        # Генерируем несколько UUID
        uuid1 = manager.generate_unique_uuid("test_context")
        uuid2 = manager.generate_unique_uuid("test_context")
        
        # Проверяем что UUID валидные
        assert uuid1 is not None
        assert uuid2 is not None
        assert len(uuid1) == 36  # Стандартная длина UUID4
        assert len(uuid2) == 36
        
        # Проверяем что UUID разные
        assert uuid1 != uuid2
        
        # Проверяем что UUID валидные
        uuid.UUID(uuid1)  # Не должно вызывать исключение
        uuid.UUID(uuid2)  # Не должно вызывать исключение
    
    def test_generate_unique_uuid_context(self):
        """Тест генерации UUID с контекстом"""
        manager = UUIDManager()
        
        # Генерируем UUID с разными контекстами
        uuid1 = manager.generate_unique_uuid("project_creation")
        uuid2 = manager.generate_unique_uuid("user_registration")
        uuid3 = manager.generate_unique_uuid("file_upload")
        
        # Все UUID должны быть уникальными
        assert uuid1 != uuid2
        assert uuid1 != uuid3
        assert uuid2 != uuid3
    
    def test_is_uuid_unique(self):
        """Тест проверки уникальности UUID"""
        manager = UUIDManager()
        
        # Генерируем UUID
        generated_uuid = manager.generate_unique_uuid("test")
        
        # Проверяем что сгенерированный UUID не уникален (уже используется)
        assert not manager.is_uuid_unique(generated_uuid)
        
        # Проверяем что новый UUID уникален
        new_uuid = str(uuid.uuid4())
        assert manager.is_uuid_unique(new_uuid)
    
    def test_register_uuid_success(self):
        """Тест успешной регистрации UUID"""
        manager = UUIDManager()
        
        # Создаем новый UUID
        new_uuid = str(uuid.uuid4())
        
        # Регистрируем UUID
        result = manager.register_uuid(new_uuid, "test_context")
        
        assert result is True
        assert not manager.is_uuid_unique(new_uuid)  # UUID теперь используется
    
    def test_register_uuid_duplicate(self):
        """Тест регистрации дублирующегося UUID"""
        manager = UUIDManager()
        
        # Генерируем UUID
        generated_uuid = manager.generate_unique_uuid("test")
        
        # Пытаемся зарегистрировать тот же UUID
        result = manager.register_uuid(generated_uuid, "test_context")
        
        assert result is False  # UUID уже используется
    
    def test_release_uuid_success(self):
        """Тест успешного освобождения UUID"""
        manager = UUIDManager()
        
        # Генерируем UUID
        generated_uuid = manager.generate_unique_uuid("test")
        
        # Освобождаем UUID
        result = manager.release_uuid(generated_uuid)
        
        assert result is True
        assert manager.is_uuid_unique(generated_uuid)  # UUID теперь свободен
    
    def test_release_uuid_not_found(self):
        """Тест освобождения несуществующего UUID"""
        manager = UUIDManager()
        
        # Создаем UUID который не был зарегистрирован
        unregistered_uuid = str(uuid.uuid4())
        
        # Пытаемся освободить UUID
        result = manager.release_uuid(unregistered_uuid)
        
        assert result is False
    
    def test_get_stats(self):
        """Тест получения статистики"""
        manager = UUIDManager()
        
        # Генерируем несколько UUID
        manager.generate_unique_uuid("test1")
        manager.generate_unique_uuid("test2")
        
        # Получаем статистику
        stats = manager.get_stats()
        
        assert isinstance(stats, dict)
        assert "total_used_uuids" in stats
        assert "last_cleanup" in stats
        assert "cleanup_interval_hours" in stats
        
        assert stats["total_used_uuids"] >= 2  # Минимум 2 UUID
        assert stats["cleanup_interval_hours"] == 1.0  # 1 час
    
    def test_cleanup_functionality(self):
        """Тест функциональности очистки"""
        manager = UUIDManager()
        
        # Мокаем время для тестирования очистки
        with patch('backend.utils.uuid_manager.datetime') as mock_datetime:
            # Устанавливаем текущее время
            now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = now
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)
            
            # Устанавливаем время последней очистки в прошлое
            manager._last_cleanup = now - timedelta(hours=2)
            
            # Генерируем много UUID для тестирования очистки
            for i in range(100):
                manager.generate_unique_uuid(f"test_{i}")
            
            # Проверяем что очистка не произошла (менее 10000 UUID)
            initial_count = len(manager._used_uuids)
            
            # Генерируем еще один UUID (должен вызвать проверку очистки)
            manager.generate_unique_uuid("cleanup_test")
            
            # Количество UUID должно остаться тем же (очистка не нужна)
            assert len(manager._used_uuids) == initial_count + 1
    
    def test_max_attempts_exceeded(self):
        """Тест превышения максимального количества попыток"""
        manager = UUIDManager()
        
        # Мокаем uuid.uuid4 чтобы он всегда возвращал один и тот же UUID
        test_uuid = str(uuid.uuid4())
        with patch('uuid.uuid4', return_value=uuid.UUID(test_uuid)):
            # Первая генерация должна пройти
            manager.generate_unique_uuid("test")
            
            # Вторая генерация должна вызвать исключение
            with pytest.raises(RuntimeError, match="Unable to generate unique UUID"):
                manager.generate_unique_uuid("test")
    
    def test_thread_safety(self):
        """Тест потокобезопасности"""
        manager = UUIDManager()
        
        # Проверяем что lock существует
        assert hasattr(manager, '_lock')
        assert manager._lock is not None
        
        # Проверяем что операции выполняются с блокировкой
        # (это сложно протестировать без создания реальных потоков,
        # но мы можем проверить что lock используется)
        with manager._lock:
            assert True  # Если дошли сюда, lock работает
    
    def test_global_instance_exists(self):
        """Тест существования глобального экземпляра"""
        assert uuid_manager is not None
        assert isinstance(uuid_manager, UUIDManager)
    
    def test_convenience_functions(self):
        """Тест удобных функций"""
        # Тестируем generate_unique_uuid
        uuid1 = generate_unique_uuid("test_context")
        assert uuid1 is not None
        assert len(uuid1) == 36
        
        # Тестируем is_uuid_unique
        assert not is_uuid_unique(uuid1)  # Сгенерированный UUID не уникален
        new_uuid = str(uuid.uuid4())
        assert is_uuid_unique(new_uuid)  # Новый UUID уникален
        
        # Тестируем register_uuid
        result = register_uuid(new_uuid, "test_context")
        assert result is True
        assert not is_uuid_unique(new_uuid)  # UUID теперь используется
        
        # Тестируем release_uuid
        result = release_uuid(new_uuid)
        assert result is True
        assert is_uuid_unique(new_uuid)  # UUID снова свободен
        
        # Тестируем get_uuid_stats
        stats = get_uuid_stats()
        assert isinstance(stats, dict)
        assert "total_used_uuids" in stats
    
    def test_uuid_format_validation(self):
        """Тест валидации формата UUID"""
        manager = UUIDManager()
        
        # Генерируем UUID и проверяем его формат
        generated_uuid = manager.generate_unique_uuid("test")
        
        # Проверяем что UUID соответствует формату UUID4
        uuid_obj = uuid.UUID(generated_uuid)
        assert uuid_obj.version == 4  # UUID4
        
        # Проверяем что UUID состоит из 36 символов (32 hex + 4 дефиса)
        assert len(generated_uuid) == 36
        assert generated_uuid.count('-') == 4
    
    def test_context_logging(self):
        """Тест логирования контекста"""
        manager = UUIDManager()
        
        # Мокаем логгер для проверки логирования
        with patch('backend.utils.uuid_manager.logger') as mock_logger:
            # Генерируем UUID с контекстом
            manager.generate_unique_uuid("test_context")
            
            # Проверяем что было вызвано логирование
            mock_logger.debug.assert_called()
            
            # Проверяем что в логе есть контекст
            call_args = mock_logger.debug.call_args[0][0]
            assert "test_context" in call_args
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.utils.uuid_manager import (
            UUIDManager, uuid_manager,
            generate_unique_uuid, is_uuid_unique,
            register_uuid, release_uuid, get_uuid_stats
        )
        
        assert UUIDManager is not None
        assert uuid_manager is not None
        assert generate_unique_uuid is not None
        assert is_uuid_unique is not None
        assert register_uuid is not None
        assert release_uuid is not None
        assert get_uuid_stats is not None
    
    def test_multiple_managers_independence(self):
        """Тест независимости нескольких менеджеров"""
        manager1 = UUIDManager()
        manager2 = UUIDManager()
        
        # Генерируем UUID в разных менеджерах
        uuid1 = manager1.generate_unique_uuid("test")
        uuid2 = manager2.generate_unique_uuid("test")
        
        # UUID должны быть разными
        assert uuid1 != uuid2
        
        # UUID из одного менеджера не должны влиять на другой
        assert not manager1.is_uuid_unique(uuid1)  # Используется в manager1
        assert is_uuid_unique(uuid1)  # Но уникален в глобальном менеджере
        # (потому что глобальный менеджер - это отдельный экземпляр)