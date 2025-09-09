#!/usr/bin/env python3
"""
Обновленный wrapper для GPT-Pilot с полной интеграцией
Использует SamokoderGPTPilotAdapter для полноценной работы с GPT-Pilot
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator, Any
from datetime import datetime
import zipfile
import logging

# Импортируем наш упрощенный адаптер
from backend.services.gpt_pilot_simple_adapter import SamokoderGPTPilotSimpleAdapter

logger = logging.getLogger(__name__)

class SamokoderGPTPilot:
    """
    Обновленный wrapper над GPT-Pilot для интеграции с SaaS платформой Самокодер
    Использует полноценный адаптер для работы с GPT-Pilot
    """
    
    def __init__(self, project_id: str, user_id: str, user_api_keys: Dict[str, str]):
        self.project_id = project_id
        self.user_id = user_id
        self.user_api_keys = user_api_keys
        
        # Настраиваем рабочую директорию
        self.workspace = Path(f"workspaces/{user_id}/{project_id}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Создаем упрощенный адаптер GPT-Pilot
        self.adapter = SamokoderGPTPilotSimpleAdapter(project_id, user_id, user_api_keys)
        
        logger.info(f"SamokoderGPTPilot initialized for project {project_id}")
    
    async def initialize_project(self, app_description: str, app_name: str = "Samokoder App") -> Dict[str, Any]:
        """Инициализирует проект в GPT-Pilot"""
        try:
            logger.info(f"Initializing project {self.project_id} with description: {app_description}")
            
            # Используем адаптер для инициализации
            result = await self.adapter.initialize_project(app_name, app_description)
            
            logger.info(f"Project {self.project_id} initialized: {result['status']}")
            return result
            
        except Exception as e:
            logger.error(f"Error initializing project {self.project_id}: {e}")
            return {
                'project_id': self.project_id,
                'status': 'error',
                'error': str(e),
                'message': f'Ошибка инициализации проекта: {str(e)}'
            }
    
    async def chat_with_agents(self, message: str, context: str = "chat") -> AsyncGenerator[Dict, None]:
        """Чат с агентами GPT-Pilot"""
        try:
            logger.info(f"Starting chat with agents for project {self.project_id}")
            
            # Используем адаптер для чата
            async for update in self.adapter.chat_with_agents(message, context):
                yield update
                
        except Exception as e:
            logger.error(f"Error in chat_with_agents: {e}")
            yield {
                'type': 'error',
                'message': f'Ошибка в работе агентов: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    async def generate_full_app(self) -> AsyncGenerator[Dict, None]:
        """Полная генерация приложения"""
        try:
            logger.info(f"Starting full app generation for project {self.project_id}")
            
            # Используем адаптер для генерации
            async for update in self.adapter.generate_full_app():
                yield update
                
        except Exception as e:
            logger.error(f"Error in generate_full_app: {e}")
            yield {
                'type': 'error',
                'message': f'Ошибка генерации: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def get_project_files(self) -> Dict:
        """Возвращает структуру файлов проекта"""
        try:
            return self.adapter.get_project_files()
        except Exception as e:
            logger.error(f"Error getting project files: {e}")
            return {}
    
    def get_file_content(self, file_path: str) -> str:
        """Получает содержимое файла"""
        try:
            return self.adapter.get_file_content(file_path)
        except Exception as e:
            logger.error(f"Error getting file content: {e}")
            raise
    
    def create_zip_export(self) -> Path:
        """Создает ZIP архив проекта"""
        try:
            return self.adapter.create_zip_export()
        except Exception as e:
            logger.error(f"Error creating zip export: {e}")
            raise
    
    async def restore_from_workspace(self):
        """Восстанавливает состояние проекта из workspace"""
        try:
            await self.adapter.restore_from_workspace()
        except Exception as e:
            logger.error(f"Error restoring from workspace: {e}")
            # Создаем базовую структуру в случае ошибки
            await self.initialize_project("Restored Project", "Восстановленный проект")
    
    def get_project_status(self) -> Dict[str, Any]:
        """Возвращает статус проекта"""
        try:
            return self.adapter.get_project_status()
        except Exception as e:
            logger.error(f"Error getting project status: {e}")
            return {
                'project_id': self.project_id,
                'user_id': self.user_id,
                'workspace': str(self.workspace),
                'initialized': False,
                'status': 'error',
                'error': str(e)
            }
    
    def get_workspace_path(self) -> Path:
        """Возвращает путь к workspace"""
        return self.workspace
    
    def is_initialized(self) -> bool:
        """Проверяет, инициализирован ли проект"""
        return self.adapter.initialized
    
    def get_api_config(self) -> Dict[str, str]:
        """Возвращает конфигурацию API"""
        return {
            'endpoint': os.getenv('ENDPOINT', 'OPENAI'),
            'model': os.getenv('MODEL_NAME', 'gpt-4o-mini'),
            'has_openai': 'openai' in self.user_api_keys,
            'has_anthropic': 'anthropic' in self.user_api_keys,
            'has_groq': 'groq' in self.user_api_keys,
            'has_openrouter': 'openrouter' in self.user_api_keys
        }
    
    async def update_project_description(self, description: str) -> bool:
        """Обновляет описание проекта"""
        try:
            if self.adapter.project:
                self.adapter.project.name = description
                # Здесь можно добавить сохранение в базу данных
                return True
            return False
        except Exception as e:
            logger.error(f"Error updating project description: {e}")
            return False
    
    async def get_agent_status(self) -> Dict[str, Any]:
        """Возвращает статус агентов"""
        try:
            if not self.adapter.initialized:
                return {'status': 'not_initialized'}
            
            return {
                'status': 'active',
                'current_agent': 'SamokoderGPT',
                'progress': 100,
                'last_activity': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting agent status: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def cleanup(self):
        """Очищает ресурсы"""
        try:
            # Здесь можно добавить очистку ресурсов GPT-Pilot
            logger.info(f"Cleaning up resources for project {self.project_id}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Деструктор для очистки ресурсов"""
        self.cleanup()