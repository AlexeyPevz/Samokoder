"""
Migration Manager для управления миграциями БД
"""
import asyncio
import subprocess
import logging
from pathlib import Path
from typing import Optional, List
from config.settings import settings

logger = logging.getLogger(__name__)

class MigrationManager:
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or self._get_database_url()
        self.alembic_config = "alembic.ini"
        
    def _get_database_url(self) -> str:
        """Получить URL БД из настроек"""
        # Используем environment variable или fallback на settings
        import os
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            return db_url
        
        # Fallback на settings (для development)
        return f"postgresql://{settings.database_user}:{settings.database_password}@{settings.database_host}:{settings.database_port}/{settings.database_name}"
    
    async def upgrade(self, revision: str = "head") -> bool:
        """Применить миграции до указанной ревизии"""
        try:
            logger.info(f"Applying migrations up to revision: {revision}")
            # Используем async subprocess для лучшей производительности
            process = await asyncio.create_subprocess_exec(
                "alembic", "upgrade", revision,
                cwd=Path(__file__).parent.parent.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "DATABASE_URL": self.database_url}
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Migration upgrade failed: {stderr.decode()}")
                return False
                
            logger.info(f"Migration upgrade successful: {stdout.decode()}")
            return True
        except Exception as e:
            logger.error(f"Migration upgrade failed: {e}")
            return False
    
    async def downgrade(self, revision: str = "-1") -> bool:
        """Откатить миграции до указанной ревизии"""
        try:
            logger.info(f"Downgrading migrations to revision: {revision}")
            # Используем async subprocess для лучшей производительности
            process = await asyncio.create_subprocess_exec(
                "alembic", "downgrade", revision,
                cwd=Path(__file__).parent.parent.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "DATABASE_URL": self.database_url}
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Migration downgrade failed: {stderr.decode()}")
                return False
                
            logger.info(f"Migration downgrade successful: {stdout.decode()}")
            return True
        except Exception as e:
            logger.error(f"Migration downgrade failed: {e}")
            return False
    
    async def current_revision(self) -> Optional[str]:
        """Получить текущую ревизию"""
        try:
            process = await asyncio.create_subprocess_exec(
                "alembic", "current",
                cwd=Path(__file__).parent.parent.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "DATABASE_URL": self.database_url}
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to get current revision: {stderr.decode()}")
                return None
                
            # Парсим вывод для получения ревизии
            output = stdout.decode().strip()
            if output and " (head)" in output:
                return output.split(" (head)")[0]
            return output if output else None
        except Exception as e:
            logger.error(f"Failed to get current revision: {e}")
            return None
    
    async def create_migration(self, message: str) -> bool:
        """Создать новую миграцию"""
        try:
            logger.info(f"Creating migration: {message}")
            process = await asyncio.create_subprocess_exec(
                "alembic", "revision", "--autogenerate", "-m", message,
                cwd=Path(__file__).parent.parent.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "DATABASE_URL": self.database_url}
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to create migration: {stderr.decode()}")
                return False
                
            logger.info(f"Migration created successfully: {stdout.decode()}")
            return True
        except Exception as e:
            logger.error(f"Failed to create migration: {e}")
            return False
    
    async def history(self) -> List[str]:
        """Получить историю миграций"""
        try:
            process = await asyncio.create_subprocess_exec(
                "alembic", "history",
                cwd=Path(__file__).parent.parent.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "DATABASE_URL": self.database_url}
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to get migration history: {stderr.decode()}")
                return []
                
            return stdout.decode().strip().split('\n')
        except Exception as e:
            logger.error(f"Failed to get migration history: {e}")
            return []
    
    async def check_migration_status(self) -> dict:
        """Проверить статус миграций"""
        current = await self.current_revision()
        history = await self.history()
        
        return {
            "current_revision": current,
            "total_migrations": len(history),
            "is_up_to_date": current and " (head)" in str(history[-1]) if history else False
        }

# Глобальный экземпляр
migration_manager = MigrationManager()