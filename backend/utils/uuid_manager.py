"""
Менеджер UUID с проверкой уникальности
Предотвращает дубликаты UUID в системе
"""

import uuid
import threading
from typing import Set, Optional
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class UUIDManager:
    """Менеджер UUID с проверкой уникальности"""
    
    def __init__(self):
        self._used_uuids: Set[str] = set()
        self._lock = threading.Lock()
        self._cleanup_interval = timedelta(hours=1)
        self._last_cleanup = datetime.now()
    
    def generate_unique_uuid(self, context: str = "general") -> str:
        """Генерирует уникальный UUID с проверкой дубликатов"""
        with self._lock:
            # Периодическая очистка старых UUID
            self._cleanup_if_needed()
            
            max_attempts = 100
            for attempt in range(max_attempts):
                new_uuid = str(uuid.uuid4())
                
                if new_uuid not in self._used_uuids:
                    self._used_uuids.add(new_uuid)
                    logger.debug(f"Generated unique UUID for context: {context}")
                    return new_uuid
            
            # Если не удалось сгенерировать уникальный UUID за 100 попыток
            logger.error(f"Failed to generate unique UUID after {max_attempts} attempts")
            raise RuntimeError("Unable to generate unique UUID")
    
    def is_uuid_unique(self, uuid_str: str) -> bool:
        """Проверяет, уникален ли UUID"""
        with self._lock:
            return uuid_str not in self._used_uuids
    
    def register_uuid(self, uuid_str: str, context: str = "manual") -> bool:
        """Регистрирует существующий UUID"""
        with self._lock:
            if uuid_str in self._used_uuids:
                logger.warning(f"UUID {uuid_str} already registered")
                return False
            
            self._used_uuids.add(uuid_str)
            logger.debug(f"Registered UUID for context: {context}")
            return True
    
    def release_uuid(self, uuid_str: str) -> bool:
        """Освобождает UUID (удаляет из списка использованных)"""
        with self._lock:
            if uuid_str in self._used_uuids:
                self._used_uuids.remove(uuid_str)
                logger.debug(f"Released UUID: {uuid_str}")
                return True
            return False
    
    def _cleanup_if_needed(self):
        """Периодическая очистка старых UUID"""
        now = datetime.now()
        if now - self._last_cleanup > self._cleanup_interval:
            # Очищаем половину UUID (самые старые)
            if len(self._used_uuids) > 10000:
                uuids_to_remove = list(self._used_uuids)[:len(self._used_uuids) // 2]
                for uuid_str in uuids_to_remove:
                    self._used_uuids.discard(uuid_str)
                
                logger.info(f"Cleaned up {len(uuids_to_remove)} old UUIDs")
            
            self._last_cleanup = now
    
    def get_stats(self) -> dict:
        """Получить статистику использования UUID"""
        with self._lock:
            return {
                "total_used_uuids": len(self._used_uuids),
                "last_cleanup": self._last_cleanup.isoformat(),
                "cleanup_interval_hours": self._cleanup_interval.total_seconds() / 3600
            }

# Глобальный экземпляр менеджера
uuid_manager = UUIDManager()

# Удобные функции для использования
def generate_unique_uuid(context: str = "general") -> str:
    """Генерирует уникальный UUID"""
    return uuid_manager.generate_unique_uuid(context)

def is_uuid_unique(uuid_str: str) -> bool:
    """Проверяет уникальность UUID"""
    return uuid_manager.is_uuid_unique(uuid_str)

def register_uuid(uuid_str: str, context: str = "manual") -> bool:
    """Регистрирует UUID"""
    return uuid_manager.register_uuid(uuid_str, context)

def release_uuid(uuid_str: str) -> bool:
    """Освобождает UUID"""
    return uuid_manager.release_uuid(uuid_str)

def get_uuid_stats() -> dict:
    """Получить статистику UUID"""
    return uuid_manager.get_stats()