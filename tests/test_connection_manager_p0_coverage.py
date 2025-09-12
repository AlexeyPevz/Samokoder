"""
P0 тесты для Connection Manager - критические пробелы в покрытии
Блокируют мёрж до зелёного прогона
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from backend.services.connection_manager import ConnectionManager, connection_manager

class TestConnectionManagerP0Coverage:
    """P0 тесты для критических пробелов в Connection Manager"""
    
    # === P0 - КРИТИЧЕСКИЕ ТЕСТЫ (БЛОКИРУЮТ МЁРЖ) ===
    
    @pytest.mark.asyncio
    async def test_get_redis_connection_success(self):
        """P0: Тест успешного получения Redis соединения"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для Redis pool
        mock_redis_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_redis_pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_redis_pool.acquire.return_value.__aexit__.return_value = None
        
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
        """P0: Тест получения Redis соединения при отсутствии pool"""
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
        """P0: Тест получения Redis соединения при неинициализированном менеджере"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Не инициализируем менеджер
        manager._initialized = False
        
        # Тестируем получение Redis соединения
        with pytest.raises(RuntimeError, match="Connection manager not initialized"):
            async with manager.get_redis_connection() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_get_redis_connection_pool_error(self):
        """P0: Тест получения Redis соединения при ошибке pool"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для Redis pool с ошибкой
        mock_redis_pool = AsyncMock()
        mock_redis_pool.acquire.side_effect = Exception("Redis connection failed")
        
        # Настраиваем mock для _pools
        manager._pools = {'redis': mock_redis_pool}
        manager._initialized = True
        
        # Тестируем получение Redis соединения
        with pytest.raises(Exception, match="Redis connection failed"):
            async with manager.get_redis_connection() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_get_database_connection_success(self):
        """P0: Тест успешного получения Database соединения"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для Database pool
        mock_db_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_db_pool.acquire.return_value.__aenter__.return_value = mock_connection
        mock_db_pool.acquire.return_value.__aexit__.return_value = None
        
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
        """P0: Тест получения Database соединения при отсутствии pool"""
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
    async def test_get_database_connection_not_initialized(self):
        """P0: Тест получения Database соединения при неинициализированном менеджере"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Не инициализируем менеджер
        manager._initialized = False
        
        # Тестируем получение Database соединения
        with pytest.raises(RuntimeError, match="Connection manager not initialized"):
            async with manager.get_database_connection() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_get_database_connection_pool_error(self):
        """P0: Тест получения Database соединения при ошибке pool"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для Database pool с ошибкой
        mock_db_pool = AsyncMock()
        mock_db_pool.acquire.side_effect = Exception("Database connection failed")
        
        # Настраиваем mock для _pools
        manager._pools = {'database': mock_db_pool}
        manager._initialized = True
        
        # Тестируем получение Database соединения
        with pytest.raises(Exception, match="Database connection failed"):
            async with manager.get_database_connection() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_get_pool_success(self):
        """P0: Тест успешного получения pool"""
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
        """P0: Тест получения несуществующего pool"""
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
        """P0: Тест получения pool при неинициализированном менеджере"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Не инициализируем менеджер
        manager._initialized = False
        
        # Тестируем получение pool
        with pytest.raises(RuntimeError, match="Connection manager not initialized"):
            manager.get_pool('test_pool')
    
    @pytest.mark.asyncio
    async def test_initialize_success(self):
        """P0: Тест успешной инициализации ConnectionManager"""
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
    async def test_initialize_redis_failure(self):
        """P0: Тест инициализации при ошибке Redis"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для supabase_manager
        with patch('backend.services.connection_manager.supabase_manager') as mock_supabase:
            mock_supabase.initialize = AsyncMock()
            
            # Настраиваем mock для RedisConnectionPool с ошибкой
            with patch('backend.services.connection_manager.RedisConnectionPool') as mock_redis_class:
                mock_redis_pool = AsyncMock()
                mock_redis_class.return_value = mock_redis_pool
                mock_redis_pool.initialize = AsyncMock(side_effect=Exception("Redis connection failed"))
                
                # Настраиваем mock для HTTPConnectionPool
                with patch('backend.services.connection_manager.HTTPConnectionPool') as mock_http_class:
                    mock_http_pool = AsyncMock()
                    mock_http_class.return_value = mock_http_pool
                    mock_http_pool.initialize = AsyncMock()
                    
                    # Настраиваем mock для settings
                    with patch('backend.services.connection_manager.settings') as mock_settings:
                        mock_settings.redis_url = "redis://localhost:6379"
                        mock_settings.database_url = None
                        
                        # Тестируем инициализацию
                        await manager.initialize()
                        
                        # Проверяем, что менеджер инициализирован
                        assert manager._initialized is True
                        assert 'supabase' in manager._pools
                        assert 'redis' in manager._pools
                        assert manager._pools['redis'] is None  # Redis должен быть None при ошибке
                        assert 'http' in manager._pools
    
    @pytest.mark.asyncio
    async def test_initialize_already_initialized(self):
        """P0: Тест повторной инициализации"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Инициализируем менеджер
        manager._initialized = True
        manager._pools = {'test': 'pool'}
        
        # Настраиваем mock для supabase_manager
        with patch('backend.services.connection_manager.supabase_manager') as mock_supabase:
            mock_supabase.initialize = AsyncMock()
            
            # Тестируем повторную инициализацию
            await manager.initialize()
            
            # Проверяем, что initialize не был вызван повторно
            mock_supabase.initialize.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_close_success(self):
        """P0: Тест успешного закрытия ConnectionManager"""
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
    
    @pytest.mark.asyncio
    async def test_close_with_errors(self):
        """P0: Тест закрытия ConnectionManager при ошибках"""
        # Создаем новый экземпляр ConnectionManager для тестирования
        manager = ConnectionManager()
        
        # Настраиваем mock для pools с ошибками
        mock_supabase = AsyncMock()
        mock_redis = AsyncMock()
        mock_redis.close.side_effect = Exception("Redis close failed")
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
            
            # Тестируем закрытие (должно продолжиться несмотря на ошибки)
            await manager.close()
            
            # Проверяем, что все pools были закрыты
            mock_redis.close.assert_called_once()
            mock_http.close.assert_called_once()
            mock_database.close.assert_called_once()
            mock_supabase_mgr.close.assert_called_once()
            
            # Проверяем, что менеджер деинициализирован
            assert manager._initialized is False
            assert len(manager._pools) == 0

class TestConnectionManagerUtilityFunctions:
    """P0 тесты для utility функций Connection Manager"""
    
    @pytest.mark.asyncio
    async def test_get_redis_connection_utility(self):
        """P0: Тест utility функции get_redis_connection"""
        from backend.services.connection_manager import get_redis_connection
        
        # Настраиваем mock для connection_manager
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_connection = AsyncMock()
            mock_manager.get_redis_connection.return_value.__aenter__.return_value = mock_connection
            mock_manager.get_redis_connection.return_value.__aexit__.return_value = None
            
            # Тестируем utility функцию
            async for conn in get_redis_connection():
                assert conn == mock_connection
                break  # Генерируем только одно значение
    
    @pytest.mark.asyncio
    async def test_get_database_connection_utility(self):
        """P0: Тест utility функции get_database_connection"""
        from backend.services.connection_manager import get_database_connection
        
        # Настраиваем mock для connection_manager
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_connection = AsyncMock()
            mock_manager.get_database_connection.return_value.__aenter__.return_value = mock_connection
            mock_manager.get_database_connection.return_value.__aexit__.return_value = None
            
            # Тестируем utility функцию
            async for conn in get_database_connection():
                assert conn == mock_connection
                break  # Генерируем только одно значение

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])