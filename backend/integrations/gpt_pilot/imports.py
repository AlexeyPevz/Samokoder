"""
GPT-Pilot Imports Module
Централизованные импорты GPT-Pilot с правильной обработкой ошибок
"""

import sys
import logging
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger(__name__)

# Путь к GPT-Pilot core
GPT_PILOT_CORE_PATH = Path(__file__).parent.parent.parent.parent / "samokoder-core"

def ensure_gpt_pilot_path():
    """Обеспечивает доступность GPT-Pilot в sys.path"""
    if str(GPT_PILOT_CORE_PATH) not in sys.path:
        sys.path.insert(0, str(GPT_PILOT_CORE_PATH))

def safe_import_gpt_pilot():
    """Безопасный импорт GPT-Pilot модулей с fallback"""
    try:
        ensure_gpt_pilot_path()
        
        # Импорты GPT-Pilot
        from core.db.models.project import Project
        from core.db.models.branch import Branch
        from core.config.user_settings import UserSettings
        from core.agents.orchestrator import Orchestrator
        from core.llm.openai_client import OpenAIClient
        from core.llm.anthropic_client import AnthropicClient
        from core.llm.groq_client import GroqClient
        from core.db.session import get_session
        from core.state.state_manager import StateManager
        from core.disk.vfs import VFS
        
        return {
            'Project': Project,
            'Branch': Branch,
            'UserSettings': UserSettings,
            'Orchestrator': Orchestrator,
            'OpenAIClient': OpenAIClient,
            'AnthropicClient': AnthropicClient,
            'GroqClient': GroqClient,
            'get_session': get_session,
            'StateManager': StateManager,
            'VFS': VFS,
            'available': True
        }
    except ImportError as e:
        logger.warning(f"GPT-Pilot not available: {e}")
        return {
            'Project': None,
            'Branch': None,
            'UserSettings': None,
            'Orchestrator': None,
            'OpenAIClient': None,
            'AnthropicClient': None,
            'GroqClient': None,
            'get_session': None,
            'StateManager': None,
            'VFS': None,
            'available': False,
            'error': str(e)
        }

# Глобальный кэш импортов
_gpt_pilot_modules: Optional[dict] = None

def get_gpt_pilot_modules() -> dict:
    """Получить GPT-Pilot модули (с кэшированием)"""
    global _gpt_pilot_modules
    if _gpt_pilot_modules is None:
        _gpt_pilot_modules = safe_import_gpt_pilot()
    return _gpt_pilot_modules

def is_gpt_pilot_available() -> bool:
    """Проверить доступность GPT-Pilot"""
    modules = get_gpt_pilot_modules()
    return modules.get('available', False)