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
        return f"postgresql://postgres:{settings.database_password}@{settings.database_host}:{settings.database_port}/{settings.database_name}"
    
    async def upgrade(self, revision: str = "head") -> bool:
        """Применить миграции до указанной ревизии"""
        try:
            logger.info(f"Applying migrations up to revision: {revision}")
            result = subprocess.run(
                ["alembic", "upgrade", revision],
                cwd=Path(__file__).parent.parent.parent,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"Migration upgrade successful: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Migration upgrade failed: {e.stderr}")
            return False
    
    async def downgrade(self, revision: str = "-1") -> bool:
        """Откатить миграции до указанной ревизии"""
        try:
            logger.info(f"Downgrading migrations to revision: {revision}")
            result = subprocess.run(
                ["alembic", "downgrade", revision],
                cwd=Path(__file__).parent.parent.parent,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"Migration downgrade successful: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Migration downgrade failed: {e.stderr}")
            return False
    
    async def current_revision(self) -> Optional[str]:
        """Получить текущую ревизию"""
        try:
            result = subprocess.run(
                ["alembic", "current"],
                cwd=Path(__file__).parent.parent.parent,
                capture_output=True,
                text=True,
                check=True
            )
            # Парсим вывод для получения ревизии
            output = result.stdout.strip()
            if output and " (head)" in output:
                return output.split(" (head)")[0]
            return output if output else None
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get current revision: {e.stderr}")
            return None
    
    async def create_migration(self, message: str) -> bool:
        """Создать новую миграцию"""
        try:
            logger.info(f"Creating migration: {message}")
            result = subprocess.run(
                ["alembic", "revision", "--autogenerate", "-m", message],
                cwd=Path(__file__).parent.parent.parent,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"Migration created successfully: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create migration: {e.stderr}")
            return False
    
    async def history(self) -> List[str]:
        """Получить историю миграций"""
        try:
            result = subprocess.run(
                ["alembic", "history"],
                cwd=Path(__file__).parent.parent.parent,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().split('\n')
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get migration history: {e.stderr}")
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