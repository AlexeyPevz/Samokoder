"""
Базовый класс для GPT-Pilot адаптеров
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class BaseGPTPilotAdapter(ABC):
    """Базовый класс для всех GPT-Pilot адаптеров"""
    
    def __init__(self, project_id: str, user_id: str, user_api_keys: Dict[str, str]):
        self.project_id = project_id
        self.user_id = user_id
        self.user_api_keys = user_api_keys
        
        # Настраиваем рабочую директорию
        self.workspace = Path(f"workspaces/{user_id}/{project_id}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Путь к GPT-Pilot
        self.gpt_pilot_path = Path("samokoder-core")
        
        # Состояние проекта
        self.project_data = None
        self.initialized = False
        
        # Настройки API
        self.setup_api_config()
        
        logger.info(f"BaseGPTPilotAdapter initialized for project {project_id}")
    
    def setup_api_config(self):
        """Настраивает API ключи из пользовательских BYOK"""
        # Приоритет: пользовательские ключи > системные fallback
        api_keys = {
            'openai': self.user_api_keys.get('openai', os.getenv('OPENAI_API_KEY')),
            'anthropic': self.user_api_keys.get('anthropic', os.getenv('ANTHROPIC_API_KEY')),
            'groq': self.user_api_keys.get('groq', os.getenv('GROQ_API_KEY'))
        }
        
        # Устанавливаем переменные окружения
        for provider, key in api_keys.items():
            if key:
                os.environ[f'{provider.upper()}_API_KEY'] = key
                logger.debug(f"Set {provider.upper()}_API_KEY")
    
    @abstractmethod
    async def initialize_project(self, project_config: Dict[str, Any]) -> bool:
        """Инициализировать проект"""
        pass
    
    @abstractmethod
    async def generate_code(self, prompt: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Сгенерировать код"""
        pass
    
    @abstractmethod
    async def get_project_status(self) -> Dict[str, Any]:
        """Получить статус проекта"""
        pass
    
    def is_initialized(self) -> bool:
        """Проверить, инициализирован ли адаптер"""
        return self.initialized