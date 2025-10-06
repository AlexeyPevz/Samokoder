from os.path import dirname, join
import os
from alembic import command
from alembic.config import Config

from samokoder.core.config.config import DBConfig
from samokoder.core.log import get_logger

log = get_logger(__name__)


def _async_to_sync_db_scheme(url: str) -> str:
    """
    Convert an async database URL to a synchronous one.

    This is needed because Alembic does not support async database
    connections.

    :param url: Asynchronouse database URL.
    :return: Synchronous database URL.
    """
    if url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql+asyncpg://", "postgresql://")
    elif url.startswith("sqlite+aiosqlite://"):
        return url.replace("sqlite+aiosqlite://", "sqlite://")
    return url


def run_migrations(config: DBConfig):
    """
    Run database migrations using Alembic.

    This needs to happen synchronously, before the asyncio
    mainloop is started, and before any database access.

    :param config: Database configuration.
    """
    url = _async_to_sync_db_scheme(config.url)
    ini_location = os.path.abspath(join(dirname(__file__), "..", "..", "alembic.ini"))

    log.debug(f"Running database migrations for {url} (config: {ini_location})")

    alembic_cfg = Config(ini_location)
    alembic_cfg.set_main_option("sqlalchemy.url", url)
    alembic_cfg.set_main_option("samokoder_runtime", "true")
    command.upgrade(alembic_cfg, "head")


__all__ = ["run_migrations"]
