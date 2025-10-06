import asyncio
import os
from copy import deepcopy
from uuid import UUID

from arq.connections import RedisSettings

# Import necessary components from the application
from samokoder.core.agents.orchestrator import Orchestrator
from samokoder.core.config import get_config
from samokoder.core.db.models import Project, User
from samokoder.core.db.session import SessionManager
from samokoder.core.state.state_manager import StateManager
from samokoder.core.ui.base import UIBase, UserInput


class ConsoleUI(UIBase):
    """A dummy UI that prints to the console, for use in the background worker."""
    async def send_message(self, message: str, *, source=None, **kwargs):
        print(f"[worker-ui|{source or 'system'}]: {message}")

    async def start(self) -> bool: return True
    async def stop(self): pass
    async def ask_question(self, question: str, **kwargs) -> UserInput:
        print(f"[worker-ui|question]: {question}")
        # Non-interactive, so we can't answer questions.
        # In a real implementation, this would need a way to signal back to the user.
        return UserInput(cancelled=True)
    async def send_project_stage(self, stage):
        print(f"[worker-ui|project_stage]: {stage.get('name')}")
    async def send_stream_chunk(self, chunk: str, **kwargs): pass
    async def send_process_status(self, status_code: int): pass


# This is the core task the worker will execute
async def run_generation_task(ctx, project_id_str: str, user_id: int):
    """
    ARQ task to run the Samokoder agent for a project.
    """
    print(f"[worker] Starting generation task for project {project_id_str} by user {user_id}")
    
    ui = ConsoleUI()
    config = deepcopy(get_config())
    session_manager = SessionManager(config.db)

    async with session_manager.get_session() as db:
        user = await db.get(User, user_id)
        project = await db.get(Project, UUID(project_id_str))

        if not user or not project:
            print(f"[worker] Error: User {user_id} or Project {project_id_str} not found.")
            return

        # This logic is copied from gpt_pilot_integration.py
        if user.api_keys:
            from samokoder.core.security.crypto import CryptoService
            from samokoder.core.config.exceptions import ConfigError

            if not config.app_secret_key:
                raise ConfigError("Cannot decrypt user API keys: APP_SECRET_KEY is not set.")

            crypto_service = CryptoService(config.app_secret_key.encode('utf-8'))
            user_settings = user.get_api_key_settings()

            for provider_name, data in user.api_keys.items():
                encrypted_key = data.get("encrypted_key") if isinstance(data, dict) else data
                if not encrypted_key: continue
                api_key = crypto_service.decrypt(encrypted_key)
                if not api_key: continue
                if hasattr(config.llm, provider_name):
                    provider_config = getattr(config.llm, provider_name)
                    provider_config.api_key = api_key

    sm = StateManager(session_manager, ui)
    await sm.load_project(project_id=project.id)

    class Namespace:
        def __init__(self):
            self.use_git = True
            self.no_check = False
            self.project = None
            self.branch = None
            self.step = None
            self.list = False
            self.list_json = False
            self.show_config = False
            self.import_v0 = None
            self.delete = None
            self.email = None
            self.extension_version = None

    orchestrator = Orchestrator(sm, ui, args=Namespace())
    
    success = False
    try:
        success = await orchestrator.run()
        print(f"[worker] Task for project {project_id_str} finished. Success: {success}")
    except Exception as e:
        print(f"[worker] Error during task for project {project_id_str}: {e}")
    finally:
        if sm.file_system and hasattr(sm.file_system, 'cleanup'):
            await sm.file_system.cleanup()

    return {"project_id": project_id_str, "success": success}


# This class defines the worker's settings, including the connection to Redis
# and the tasks it should listen for.
class WorkerSettings:
    functions = [run_generation_task]
    redis_settings = RedisSettings(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
    )
