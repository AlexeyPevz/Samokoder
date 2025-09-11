"""
Безопасный менеджер переменных окружения
Изолирует переменные окружения для каждого пользователя/проекта
"""

import os
import threading
from typing import Dict, Optional, Any
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

class EnvironmentManager:
    """Безопасный менеджер переменных окружения"""
    
    def __init__(self):
        self._local_storage = threading.local()
        self._original_env = {}
    
    def _get_user_env(self) -> Dict[str, str]:
        """Получить изолированное окружение для текущего потока"""
        if not hasattr(self._local_storage, 'user_env'):
            self._local_storage.user_env = {}
        return self._local_storage.user_env
    
    def set_user_api_keys(self, user_id: str, api_keys: Dict[str, str]) -> None:
        """Установить API ключи пользователя в изолированное окружение"""
        user_env = self._get_user_env()
        
        # Очищаем предыдущие ключи пользователя
        keys_to_remove = [k for k in user_env.keys() if k.endswith('_API_KEY')]
        for key in keys_to_remove:
            user_env.pop(key, None)
        
        # Устанавливаем новые ключи
        for provider, api_key in api_keys.items():
            if provider == 'openrouter':
                user_env['OPENROUTER_API_KEY'] = api_key
                user_env['MODEL_NAME'] = 'deepseek/deepseek-v3'
                user_env['ENDPOINT'] = 'OPENROUTER'
            elif provider == 'openai':
                user_env['OPENAI_API_KEY'] = api_key
                user_env['MODEL_NAME'] = 'gpt-4o-mini'
                user_env['ENDPOINT'] = 'OPENAI'
            elif provider == 'anthropic':
                user_env['ANTHROPIC_API_KEY'] = api_key
                user_env['MODEL_NAME'] = 'claude-3-haiku-20240307'
                user_env['ENDPOINT'] = 'ANTHROPIC'
            elif provider == 'groq':
                user_env['GROQ_API_KEY'] = api_key
                user_env['MODEL_NAME'] = 'llama-3-8b-8192'
                user_env['ENDPOINT'] = 'GROQ'
        
        logger.info(f"Set API keys for user {user_id} in isolated environment")
    
    def get_user_env_var(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Получить переменную окружения из изолированного окружения пользователя"""
        user_env = self._get_user_env()
        return user_env.get(key, default)
    
    def get_global_env_var(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Получить глобальную переменную окружения"""
        return os.getenv(key, default)
    
    @contextmanager
    def isolated_environment(self, user_id: str, api_keys: Dict[str, str]):
        """Контекстный менеджер для изолированного окружения"""
        # Сохраняем текущее состояние
        original_user_env = self._get_user_env().copy()
        
        try:
            # Устанавливаем изолированное окружение
            self.set_user_api_keys(user_id, api_keys)
            yield self
        finally:
            # Восстанавливаем исходное состояние
            self._local_storage.user_env = original_user_env
            logger.info(f"Restored environment for user {user_id}")
    
    def clear_user_environment(self, user_id: str) -> None:
        """Очистить изолированное окружение пользователя"""
        self._local_storage.user_env = {}
        logger.info(f"Cleared environment for user {user_id}")
    
    def get_environment_info(self) -> Dict[str, Any]:
        """Получить информацию о текущем окружении (без чувствительных данных)"""
        user_env = self._get_user_env()
        
        return {
            "user_env_keys": list(user_env.keys()),
            "has_openrouter": 'OPENROUTER_API_KEY' in user_env,
            "has_openai": 'OPENAI_API_KEY' in user_env,
            "has_anthropic": 'ANTHROPIC_API_KEY' in user_env,
            "has_groq": 'GROQ_API_KEY' in user_env,
            "model": user_env.get('MODEL_NAME', 'unknown'),
            "endpoint": user_env.get('ENDPOINT', 'unknown')
        }

# Глобальный экземпляр менеджера
environment_manager = EnvironmentManager()

# Удобные функции для использования
def set_user_api_keys(user_id: str, api_keys: Dict[str, str]) -> None:
    """Установить API ключи пользователя"""
    environment_manager.set_user_api_keys(user_id, api_keys)

def get_user_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
    """Получить переменную окружения пользователя"""
    return environment_manager.get_user_env_var(key, default)

def get_global_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
    """Получить глобальную переменную окружения"""
    return environment_manager.get_global_env_var(key, default)

@contextmanager
def isolated_environment(user_id: str, api_keys: Dict[str, str]):
    """Контекстный менеджер для изолированного окружения"""
    with environment_manager.isolated_environment(user_id, api_keys) as env:
        yield env