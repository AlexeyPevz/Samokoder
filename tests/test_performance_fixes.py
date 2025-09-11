"""
Тесты производительности для проверки исправлений
"""

import pytest
import asyncio
import time
import psutil
import os
from unittest.mock import Mock, patch
from backend.services.rate_limiter import RateLimiter
from backend.services.cache_service import CacheService
from backend.utils.uuid_manager import UUIDManager
from backend.services.transaction_manager import TransactionManager
from backend.services.encryption_service import EncryptionService

class TestPerformanceFixes:
    """Тесты производительности"""
    
    def test_rate_limiter_performance(self):
        """Тест производительности rate limiter"""
        rate_limiter = RateLimiter()
        
        # Тест производительности проверки rate limit
        start_time = time.time()
        
        for i in range(1000):
            asyncio.run(rate_limiter.check_rate_limit(
                f"user_{i}", "test_endpoint", 100, 1000
            ))
        
        end_time = time.time()
        duration = end_time - start_time
        
        # 1000 проверок должны выполняться быстро
        assert duration < 1.0  # Менее 1 секунды
        
        print(f"Rate limiter performance: {duration:.3f}s for 1000 checks")
    
    def test_cache_performance(self):
        """Тест производительности кэша"""
        cache_service = CacheService()
        
        # Тест производительности генерации ключей
        start_time = time.time()
        
        for i in range(1000):
            messages = [{"role": "user", "content": f"test message {i}"}]
            cache_service._generate_key(messages, "test_model", "test_provider")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # 1000 генераций ключей должны выполняться быстро
        assert duration < 0.5  # Менее 0.5 секунды
        
        print(f"Cache key generation performance: {duration:.3f}s for 1000 keys")
    
    def test_uuid_generation_performance(self):
        """Тест производительности генерации UUID"""
        uuid_manager = UUIDManager()
        
        # Тест производительности генерации уникальных UUID
        start_time = time.time()
        
        uuids = []
        for i in range(1000):
            uuid_str = uuid_manager.generate_unique_uuid("performance_test")
            uuids.append(uuid_str)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # 1000 UUID должны генерироваться быстро
        assert duration < 0.5  # Менее 0.5 секунды
        
        # Все UUID должны быть уникальными
        assert len(set(uuids)) == len(uuids)
        
        print(f"UUID generation performance: {duration:.3f}s for 1000 UUIDs")
    
    def test_encryption_performance(self):
        """Тест производительности шифрования"""
        encryption_service = EncryptionService()
        
        # Тест производительности шифрования
        test_data = "test_data_" * 100  # 1000 символов
        
        start_time = time.time()
        
        for i in range(100):
            encrypted = encryption_service.encrypt(test_data)
            decrypted = encryption_service.decrypt(encrypted)
            assert decrypted == test_data
        
        end_time = time.time()
        duration = end_time - start_time
        
        # 100 операций шифрования/дешифрования должны выполняться быстро
        assert duration < 2.0  # Менее 2 секунд
        
        print(f"Encryption performance: {duration:.3f}s for 100 operations")
    
    def test_transaction_performance(self):
        """Тест производительности транзакций"""
        transaction_manager = TransactionManager()
        
        async def test_transaction_performance():
            start_time = time.time()
            
            for i in range(100):
                async with transaction_manager.transaction() as txn_id:
                    await transaction_manager.add_operation(
                        txn_id, "insert", "test_table", {"id": i, "data": f"test_{i}"}
                    )
            
            end_time = time.time()
            duration = end_time - start_time
            
            # 100 транзакций должны выполняться быстро
            assert duration < 1.0  # Менее 1 секунды
            
            print(f"Transaction performance: {duration:.3f}s for 100 transactions")
        
        asyncio.run(test_transaction_performance())
    
    def test_memory_usage(self):
        """Тест использования памяти"""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Создаем много объектов
        rate_limiter = RateLimiter()
        cache_service = CacheService()
        uuid_manager = UUIDManager()
        encryption_service = EncryptionService()
        
        # Добавляем много данных
        for i in range(10000):
            rate_limiter.memory_store[f"user_{i}"] = {
                'minute': {'count': 1, 'window': 0},
                'hour': {'count': 1, 'window': 0}
            }
        
        # Проверяем автоочистку
        rate_limiter._auto_cleanup_if_needed()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Увеличение памяти должно быть разумным
        assert memory_increase < 100  # Менее 100 MB
        
        print(f"Memory usage: {memory_increase:.2f} MB increase")
    
    def test_concurrent_performance(self):
        """Тест производительности при конкурентном доступе"""
        rate_limiter = RateLimiter()
        uuid_manager = UUIDManager()
        
        async def concurrent_rate_limit_check():
            tasks = []
            for i in range(100):
                task = asyncio.create_task(
                    rate_limiter.check_rate_limit(f"user_{i}", "test", 100, 1000)
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            return results
        
        async def concurrent_uuid_generation():
            tasks = []
            for i in range(100):
                task = asyncio.create_task(
                    asyncio.to_thread(uuid_manager.generate_unique_uuid, f"concurrent_{i}")
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            return results
        
        # Тест конкурентного rate limiting
        start_time = time.time()
        asyncio.run(concurrent_rate_limit_check())
        rate_limit_duration = time.time() - start_time
        
        # Тест конкурентной генерации UUID
        start_time = time.time()
        uuids = asyncio.run(concurrent_uuid_generation())
        uuid_duration = time.time() - start_time
        
        # Конкурентные операции должны выполняться быстро
        assert rate_limit_duration < 1.0
        assert uuid_duration < 1.0
        
        # Все UUID должны быть уникальными
        assert len(set(uuids)) == len(uuids)
        
        print(f"Concurrent rate limiting: {rate_limit_duration:.3f}s")
        print(f"Concurrent UUID generation: {uuid_duration:.3f}s")
    
    def test_database_operation_performance(self):
        """Тест производительности операций с БД"""
        from backend.services.supabase_manager import execute_supabase_operation
        
        async def test_db_performance():
            start_time = time.time()
            
            # Симулируем операции с БД
            for i in range(50):
                try:
                    # Это будет mock операция
                    await execute_supabase_operation(
                        lambda client: client.table("test").select("*").limit(1),
                        "anon"
                    )
                except Exception:
                    # Ожидаем ошибку, так как БД не настроена
                    pass
            
            end_time = time.time()
            duration = end_time - start_time
            
            # 50 операций должны выполняться быстро
            assert duration < 2.0  # Менее 2 секунд
            
            print(f"Database operations performance: {duration:.3f}s for 50 operations")
        
        asyncio.run(test_db_performance())
    
    def test_error_handling_performance(self):
        """Тест производительности обработки ошибок"""
        from backend.utils.secure_logging import SecureLogger
        
        secure_logger = SecureLogger("performance_test")
        
        start_time = time.time()
        
        # Тест производительности санитизации логов
        for i in range(1000):
            test_data = {
                "user_id": f"user_{i}",
                "password": f"password_{i}",
                "api_key": f"key_{i}",
                "message": f"test message {i}"
            }
            secure_logger._sanitize_dict(test_data)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # 1000 санитизаций должны выполняться быстро
        assert duration < 0.5  # Менее 0.5 секунды
        
        print(f"Log sanitization performance: {duration:.3f}s for 1000 operations")

class TestScalability:
    """Тесты масштабируемости"""
    
    def test_large_dataset_performance(self):
        """Тест производительности с большими данными"""
        rate_limiter = RateLimiter()
        
        # Добавляем много пользователей
        start_time = time.time()
        
        for i in range(50000):
            rate_limiter.memory_store[f"user_{i}"] = {
                'minute': {'count': 1, 'window': 0},
                'hour': {'count': 1, 'window': 0}
            }
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Добавление 50,000 записей должно выполняться быстро
        assert duration < 2.0  # Менее 2 секунд
        
        # Проверяем автоочистку
        cleanup_start = time.time()
        rate_limiter._auto_cleanup_if_needed()
        cleanup_duration = time.time() - cleanup_start
        
        # Автоочистка должна быть быстрой
        assert cleanup_duration < 1.0  # Менее 1 секунды
        
        print(f"Large dataset performance: {duration:.3f}s for 50,000 records")
        print(f"Cleanup performance: {cleanup_duration:.3f}s")
    
    def test_memory_efficiency(self):
        """Тест эффективности использования памяти"""
        import gc
        
        # Измеряем память до создания объектов
        gc.collect()
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Создаем много объектов
        objects = []
        for i in range(1000):
            obj = {
                'id': i,
                'data': f"test_data_{i}" * 100,
                'metadata': {'created_at': time.time(), 'updated_at': time.time()}
            }
            objects.append(obj)
        
        # Измеряем память после создания
        gc.collect()
        after_creation_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Удаляем объекты
        del objects
        gc.collect()
        
        # Измеряем память после удаления
        after_deletion_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_used = after_creation_memory - initial_memory
        memory_freed = after_creation_memory - after_deletion_memory
        
        # Память должна освобождаться
        assert memory_freed > 0
        
        print(f"Memory efficiency: {memory_used:.2f} MB used, {memory_freed:.2f} MB freed")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])