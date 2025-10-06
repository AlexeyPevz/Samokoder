from alembic.config import Config
from alembic import command
import os

def run_alembic_migrations(connection):
    alembic_cfg = Config(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'alembic.ini'))
    alembic_cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), '..', '..', '..', 'alembic'))
    alembic_cfg.set_main_option("sqlalchemy.url", str(connection.url))
    alembic_cfg.attributes["connection"] = connection
    command.upgrade(alembic_cfg, "head")
