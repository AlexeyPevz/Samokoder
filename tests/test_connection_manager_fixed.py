"""
Исправленные тесты для Connection Manager с правильными фикстурами
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from backend.services.connection_manager import ConnectionManager

class TestConnectionManagerFixed:
    """Исправленные тесты для Connection Manager"""
    
    @pytest.mark.asyncio
    async def test_get_redis_connection_success(self):
        """Тест успешного получения Redis соединения"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для Redis pool
        mock_redis_pool = MagicMock()
        mock_connection = MagicMock()
        
        # Создаем правильный async context manager
        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_connection
        mock_context_manager.__aexit__.return_value = None
        mock_redis_pool.acquire.return_value = mock_context_manager
        
        # Настраиваем mock для _pools
        manager._pools = {'redis': mock_redis_pool}
        manager._initialized = True
        
        # Тестируем получение Redis соединения
        async with manager.get_redis_connection() as conn:
            assert conn == mock_connection
        
        # Проверяем, что acquire был вызван
        mock_redis_pool.acquire.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_redis_connection_pool_not_found(self):
        """Тест получения Redis соединения при отсутствии pool"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для _pools без Redis
        manager._pools = {}
        manager._initialized = True
        
        # Тестируем получение Redis соединения
        with pytest.raises(ValueError, match="Connection pool 'redis' not found"):
            async with manager.get_redis_connection() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_get_redis_connection_not_initialized(self):
        """Тест получения Redis соединения при неинициализированном менеджере"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Не инициализируем менеджер
        manager._initialized = False
        
        # Тестируем получение Redis соединения
        with pytest.raises(RuntimeError, match="Connection manager not initialized"):
            async with manager.get_redis_connection() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_get_database_connection_success(self):
        """Тест успешного получения Database соединения"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для Database pool
        mock_db_pool = MagicMock()
        mock_connection = MagicMock()
        
        # Создаем правильный async context manager
        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_connection
        mock_context_manager.__aexit__.return_value = None
        mock_db_pool.acquire.return_value = mock_context_manager
        
        # Настраиваем mock для _pools
        manager._pools = {'database': mock_db_pool}
        manager._initialized = True
        
        # Тестируем получение Database соединения
        async with manager.get_database_connection() as conn:
            assert conn == mock_connection
        
        # Проверяем, что acquire был вызван
        mock_db_pool.acquire.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_database_connection_pool_not_found(self):
        """Тест получения Database соединения при отсутствии pool"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для _pools без Database
        manager._pools = {}
        manager._initialized = True
        
        # Тестируем получение Database соединения
        with pytest.raises(ValueError, match="Connection pool 'database' not found"):
            async with manager.get_database_connection() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_get_pool_success(self):
        """Тест успешного получения pool"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для _pools
        mock_pool = MagicMock()
        manager._pools = {'test_pool': mock_pool}
        manager._initialized = True
        
        # Тестируем получение pool
        result = manager.get_pool('test_pool')
        assert result == mock_pool
    
    @pytest.mark.asyncio
    async def test_get_pool_not_found(self):
        """Тест получения несуществующего pool"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для _pools
        manager._pools = {}
        manager._initialized = True
        
        # Тестируем получение несуществующего pool
        with pytest.raises(ValueError, match="Connection pool 'nonexistent' not found"):
            manager.get_pool('nonexistent')
    
    @pytest.mark.asyncio
    async def test_get_pool_not_initialized(self):
        """Тест получения pool при неинициализированном менеджере"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Не инициализируем менеджер
        manager._initialized = False
        
        # Тестируем получение pool
        with pytest.raises(RuntimeError, match="Connection manager not initialized"):
            manager.get_pool('test_pool')
    
    @pytest.mark.asyncio
    async def test_initialize_success(self):
        """Тест успешной инициализации ConnectionManager"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для supabase_manager
        with patch('backend.services.connection_manager.supabase_manager') as mock_supabase:
            mock_supabase.initialize = AsyncMock()
            
            # Настраиваем mock для RedisConnectionPool
            with patch('backend.services.connection_manager.RedisConnectionPool') as mock_redis_class:
                mock_redis_pool = AsyncMock()
                mock_redis_class.return_value = mock_redis_pool
                mock_redis_pool.initialize = AsyncMock()
                
                # Настраиваем mock для HTTPConnectionPool
                with patch('backend.services.connection_manager.HTTPConnectionPool') as mock_http_class:
                    mock_http_pool = AsyncMock()
                    mock_http_class.return_value = mock_http_pool
                    mock_http_pool.initialize = AsyncMock()
                    
                    # Настраиваем mock для settings
                    with patch('backend.services.connection_manager.settings') as mock_settings:
                        mock_settings.redis_url = "redis://localhost:6379"
                        mock_settings.database_url = None  # Не инициализируем database
                        
                        # Тестируем инициализацию
                        await manager.initialize()
                        
                        # Проверяем, что менеджер инициализирован
                        assert manager._initialized is True
                        assert 'supabase' in manager._pools
                        assert 'redis' in manager._pools
                        assert 'http' in manager._pools
                        
                        # Проверяем, что методы инициализации были вызваны
                        mock_supabase.initialize.assert_called_once()
                        mock_redis_pool.initialize.assert_called_once_with("redis://localhost:6379")
                        mock_http_pool.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_close_success(self):
        """Тест успешного закрытия ConnectionManager"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для pools
        mock_supabase = AsyncMock()
        mock_redis = AsyncMock()
        mock_http = AsyncMock()
        mock_database = AsyncMock()
        
        manager._pools = {
            'supabase': mock_supabase,
            'redis': mock_redis,
            'http': mock_http,
            'database': mock_database
        }
        manager._initialized = True
        
        # Настраиваем mock для supabase_manager
        with patch('backend.services.connection_manager.supabase_manager') as mock_supabase_mgr:
            mock_supabase_mgr.close = AsyncMock()
            
            # Тестируем закрытие
            await manager.close()
            
            # Проверяем, что все pools были закрыты
            mock_redis.close.assert_called_once()
            mock_http.close.assert_called_once()
            mock_database.close.assert_called_once()
            mock_supabase_mgr.close.assert_called_once()
            
            # Проверяем, что менеджер деинициализирован
            assert manager._initialized is False
            assert len(manager._pools) == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])