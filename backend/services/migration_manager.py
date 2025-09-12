"""
Migration Manager для управления миграциями БД
"""
import asyncio
import os
import subprocess
import logging
import re
import shlex
from pathlib import Path
from typing import Optional, List
from config.settings import settings

logger = logging.getLogger(__name__)

class MigrationManager:
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or self._get_database_url()
        self.alembic_config = "alembic.ini"
        # Rate limiting для subprocess вызовов
        self._last_command_time = 0
        self._command_cooldown = 1.0  # 1 секунда между командами
        
    def _get_database_url(self) -> str:
        """Получить URL БД из настроек"""
        # Используем environment variable или fallback на settings
        import os
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            return db_url
        
        # Fallback на settings (для development)
        if hasattr(settings, 'database_url') and settings.database_url:
            return settings.database_url
        else:
            # Возвращаем пустую строку если нет настроек БД
            return ""
    
    def _validate_revision(self, revision: str) -> bool:
        """Валидация ревизии миграции"""
        # Разрешенные значения ревизий
        allowed_patterns = [
            r'^head$',           # head
            r'^-?\d+$',          # числа и отрицательные числа
            r'^[a-f0-9]{12}$',   # хеши alembic
            r'^base$',           # base
        ]
        
        for pattern in allowed_patterns:
            if re.match(pattern, revision, re.IGNORECASE):
                return True
        
        logger.warning(f"Invalid revision format: {revision}")
        return False
    
    def _validate_message(self, message: str) -> bool:
        """Валидация сообщения миграции"""
        # Проверяем на опасные символы
        dangerous_patterns = [
            r'[;&|`$]',          # shell метасимволы
            r'\.\./',            # path traversal
            r'<|>',              # перенаправление
            r'\(|\)',            # подстановка команд
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, message):
                logger.warning(f"Dangerous characters in message: {message}")
                return False
        
        # Проверяем длину
        if len(message) > 200:
            logger.warning(f"Message too long: {len(message)} characters")
            return False
        
        return True
    
    async def _rate_limit_check(self) -> bool:
        """Проверка rate limiting для команд"""
        import time
        current_time = time.time()
        
        if current_time - self._last_command_time < self._command_cooldown:
            logger.warning("Rate limit exceeded for migration commands")
            return False
        
        self._last_command_time = current_time
        return True
    
    async def _safe_execute_command(self, command: List[str], operation: str) -> tuple[bool, str, str]:
        """Безопасное выполнение команды с валидацией"""
        try:
            # Проверяем rate limiting
            if not await self._rate_limit_check():
                return False, "", "Rate limit exceeded"
            
            # Валидируем команду
            if not command or command[0] != "alembic":
                logger.error(f"Invalid command: {command}")
                return False, "", "Invalid command"
            
            # Выполняем команду
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=Path(__file__).parent.parent.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "DATABASE_URL": self.database_url}
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                logger.error(f"Migration {operation} failed: {error_msg}")
                return False, "", error_msg
            
            success_msg = stdout.decode()
            logger.info(f"Migration {operation} successful: {success_msg}")
            return True, success_msg, ""
            
        except Exception as e:
            error_msg = f"Migration {operation} failed: {e}"
            logger.error(error_msg)
            return False, "", error_msg
    
    async def upgrade(self, revision: str = "head") -> bool:
        """Применить миграции до указанной ревизии"""
        # Валидируем ревизию
        if not self._validate_revision(revision):
            logger.error(f"Invalid revision: {revision}")
            return False
        
        logger.info(f"Applying migrations up to revision: {revision}")
        
        # Безопасное выполнение команды
        success, stdout, stderr = await self._safe_execute_command(
            ["alembic", "upgrade", revision], 
            "upgrade"
        )
        
        return success
    
    async def downgrade(self, revision: str = "-1") -> bool:
        """Откатить миграции до указанной ревизии"""
        # Валидируем ревизию
        if not self._validate_revision(revision):
            logger.error(f"Invalid revision: {revision}")
            return False
        
        logger.info(f"Downgrading migrations to revision: {revision}")
        
        # Безопасное выполнение команды
        success, stdout, stderr = await self._safe_execute_command(
            ["alembic", "downgrade", revision], 
            "downgrade"
        )
        
        return success
    
    async def current_revision(self) -> Optional[str]:
        """Получить текущую ревизию"""
        # Безопасное выполнение команды
        success, stdout, stderr = await self._safe_execute_command(
            ["alembic", "current"], 
            "current_revision"
        )
        
        if not success:
            return None
        
        # Парсим вывод для получения ревизии
        output = stdout.strip()
        if output and " (head)" in output:
            return output.split(" (head)")[0]
        return output if output else None
    
    async def create_migration(self, message: str) -> bool:
        """Создать новую миграцию"""
        # Валидируем сообщение
        if not self._validate_message(message):
            logger.error(f"Invalid migration message: {message}")
            return False
        
        logger.info(f"Creating migration: {message}")
        
        # Безопасное выполнение команды
        success, stdout, stderr = await self._safe_execute_command(
            ["alembic", "revision", "--autogenerate", "-m", message], 
            "create_migration"
        )
        
        return success
    
    async def history(self) -> List[str]:
        """Получить историю миграций"""
        # Безопасное выполнение команды
        success, stdout, stderr = await self._safe_execute_command(
            ["alembic", "history"], 
            "history"
        )
        
        if not success:
            return []
        
        return stdout.strip().split('\n') if stdout.strip() else []
    
    async def check_migration_status(self) -> dict:
        """Проверить статус миграций"""
        current = await self.current_revision()
        history = await self.history()
        
        return {
            "current_revision": current,
            "history": history,
            "total_migrations": len(history),
            "is_up_to_date": current and " (head)" in str(history[-1]) if history else False
        }

# Глобальный экземпляр
migration_manager = MigrationManager()