"""
Централизованный Supabase Connection Manager
Управляет всеми Supabase соединениями с connection pooling и async поддержкой
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor

from supabase import create_client, Client
from config.settings import settings

logger = logging.getLogger(__name__)

@dataclass
class SupabaseConfig:
    """Конфигурация Supabase соединений"""
    max_connections: int = 10
    connection_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: float = 1.0
    health_check_interval: int = 60  # секунды

class SupabaseConnectionManager:
    """Менеджер Supabase соединений с пулом и async поддержкой"""
    
    def __init__(self, config: SupabaseConfig = None):
        self.config = config or SupabaseConfig()
        self._clients: Dict[str, Client] = {}
        self._thread_pool = ThreadPoolExecutor(max_workers=self.config.max_connections)
        self._health_status: Dict[str, bool] = {}
        self._last_health_check: Dict[str, datetime] = {}
        self._lock = threading.Lock()
        self._initialized = False
    
    async def initialize(self):
        """Инициализация менеджера соединений"""
        if self._initialized:
            return
        
        try:
            # Создаем основные клиенты
            await self._create_clients()
            self._initialized = True
            logger.info("Supabase connection manager initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Supabase connection manager: {e}")
            raise
    
    async def _create_clients(self):
        """Создание Supabase клиентов"""
        clients_to_create = [
            ("anon", settings.supabase_url, settings.supabase_anon_key),
            ("service_role", settings.supabase_url, settings.supabase_service_role_key)
        ]
        
        for name, url, key in clients_to_create:
            if url and key and not url.endswith("example.supabase.co"):
                try:
                    # Создаем клиент в отдельном потоке
                    loop = asyncio.get_running_loop()
                    client = await loop.run_in_executor(
                        self._thread_pool,
                        self._create_sync_client,
                        url, key
                    )
                    self._clients[name] = client
                    self._health_status[name] = True
                    logger.info(f"Supabase {name} client created")
                except Exception as e:
                    logger.error(f"Failed to create Supabase {name} client: {e}")
                    self._health_status[name] = False
    
    def _create_sync_client(self, url: str, key: str) -> Client:
        """Создание синхронного Supabase клиента"""
        return create_client(url, key)
    
    def get_client(self, client_type: str = "anon") -> Optional[Client]:
        """Получить Supabase клиент"""
        if not self._initialized:
            logger.warning("Supabase connection manager not initialized")
            return None
        
        client = self._clients.get(client_type)
        if not client:
            logger.warning(f"Supabase {client_type} client not available")
            return None
        
        # Проверяем здоровье клиента
        if not self._is_client_healthy(client_type):
            logger.warning(f"Supabase {client_type} client is unhealthy")
            return None
        
        return client
    
    def _is_client_healthy(self, client_type: str) -> bool:
        """Проверка здоровья клиента"""
        if client_type not in self._health_status:
            return False
        
        # Проверяем, не устарела ли проверка здоровья
        last_check = self._last_health_check.get(client_type)
        if last_check and datetime.now() - last_check < timedelta(seconds=self.config.health_check_interval):
            return self._health_status[client_type]
        
        # Выполняем проверку здоровья
        try:
            client = self._clients.get(client_type)
            if not client:
                return False
            
            # Простая проверка - пытаемся выполнить запрос
            result = client.table("profiles").select("id").limit(1).execute()
            self._health_status[client_type] = True
            self._last_health_check[client_type] = datetime.now()
            return True
        except Exception as e:
            logger.warning(f"Supabase {client_type} health check failed: {e}")
            self._health_status[client_type] = False
            self._last_health_check[client_type] = datetime.now()
            return False
    
    async def execute_async(self, operation, client_type: str = "anon", *args, **kwargs):
        """Выполнение Supabase операции в async контексте"""
        client = self.get_client(client_type)
        if not client:
            raise RuntimeError(f"Supabase {client_type} client not available")
        
        try:
            # Выполняем операцию в отдельном потоке
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                self._thread_pool,
                self._execute_sync_operation,
                operation, client, *args, **kwargs
            )
            return result
        except Exception as e:
            logger.error(f"Supabase async operation failed: {e}")
            raise
    
    def _execute_sync_operation(self, operation, client: Client, *args, **kwargs):
        """Выполнение синхронной Supabase операции"""
        if callable(operation):
            return operation(client, *args, **kwargs)
        else:
            # Если operation - это строка с методом
            method = getattr(client, operation)
            return method(*args, **kwargs)
    
    @asynccontextmanager
    async def get_connection(self, client_type: str = "anon"):
        """Контекстный менеджер для получения соединения"""
        client = self.get_client(client_type)
        if not client:
            raise RuntimeError(f"Supabase {client_type} client not available")
        
        try:
            yield client
        except Exception as e:
            logger.error(f"Supabase connection error: {e}")
            raise
        finally:
            # Здесь можно добавить логику очистки соединения
            pass
    
    async def health_check_all(self) -> Dict[str, Any]:
        """Проверка здоровья всех клиентов"""
        results = {}
        for client_type in self._clients.keys():
            results[client_type] = {
                "healthy": self._is_client_healthy(client_type),
                "last_check": self._last_health_check.get(client_type),
                "available": client_type in self._clients
            }
        return results
    
    async def close(self):
        """Закрытие всех соединений"""
        try:
            self._clients.clear()
            self._health_status.clear()
            self._last_health_check.clear()
            self._thread_pool.shutdown(wait=True)
            self._initialized = False
            logger.info("Supabase connection manager closed")
        except Exception as e:
            logger.error(f"Error closing Supabase connection manager: {e}")

# Глобальный экземпляр менеджера
supabase_manager = SupabaseConnectionManager()

# Удобные функции для использования
async def get_supabase_client(client_type: str = "anon") -> Optional[Client]:
    """Получить Supabase клиент"""
    return supabase_manager.get_client(client_type)

async def execute_supabase_operation(operation, client_type: str = "anon", *args, **kwargs):
    """Выполнить Supabase операцию"""
    return await supabase_manager.execute_async(operation, client_type, *args, **kwargs)

@asynccontextmanager
async def supabase_connection(client_type: str = "anon"):
    """Контекстный менеджер для Supabase соединения"""
    async with supabase_manager.get_connection(client_type) as client:
        yield client