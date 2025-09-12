"""
Реальный адаптер для интеграции с GPT-Pilot
Подключается к реальному GPT-Pilot коду и выполняет генерацию
"""

import asyncio
import os
import sys
import json
import uuid
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator, Any
from datetime import datetime
import logging

from .base_adapter import BaseGPTPilotAdapter

logger = logging.getLogger(__name__)

class SamokoderGPTPilotRealAdapter(BaseGPTPilotAdapter):
    """
    Реальный адаптер для интеграции с GPT-Pilot
    Подключается к реальному GPT-Pilot коду
    """
    
    def __init__(self, project_id: str, user_id: str, user_api_keys: Dict[str, str]):
        super().__init__(project_id, user_id, user_api_keys)
        
        # GPT-Pilot модули
        self.gpt_pilot_modules = None
        self.orchestrator = None
        self.state_manager = None
        
        logger.info(f"SamokoderGPTPilotRealAdapter initialized for project {project_id}")
    
    async def initialize_project(self, project_config: Dict[str, Any]) -> bool:
        """Инициализировать проект с GPT-Pilot"""
        try:
            # Загружаем GPT-Pilot модули
            await self._load_gpt_pilot_modules()
            
            # Создаем проект
            await self._create_gpt_pilot_project(project_config)
            
            # Инициализируем оркестратор
            await self._initialize_orchestrator()
            
            self.initialized = True
            logger.info(f"Project {self.project_id} initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize project {self.project_id}: {e}")
            return False
    
    async def generate_code(self, prompt: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Сгенерировать код через GPT-Pilot"""
        if not self.initialized:
            raise RuntimeError("Adapter not initialized")
        
        try:
            # Выполняем генерацию через оркестратор
            result = await self._execute_generation(prompt, context or {})
            
            return {
                "success": True,
                "generated_code": result.get("code", ""),
                "files": result.get("files", []),
                "metadata": result.get("metadata", {}),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Code generation failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def get_project_status(self) -> Dict[str, Any]:
        """Получить статус проекта"""
        return {
            "project_id": self.project_id,
            "user_id": self.user_id,
            "initialized": self.initialized,
            "workspace": str(self.workspace),
            "gpt_pilot_available": self.gpt_pilot_modules is not None,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _load_gpt_pilot_modules(self):
        """Загрузить GPT-Pilot модули"""
        try:
            from backend.integrations.gpt_pilot.imports import get_gpt_pilot_modules
            
            self.gpt_pilot_modules = get_gpt_pilot_modules()
            
            if not self.gpt_pilot_modules.get('available', False):
                raise ImportError("GPT-Pilot modules not available")
            
            logger.info("GPT-Pilot modules loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load GPT-Pilot modules: {e}")
            raise
    
    async def _create_gpt_pilot_project(self, project_config: Dict[str, Any]):
        """Создать проект в GPT-Pilot"""
        try:
            Project = self.gpt_pilot_modules['Project']
            
            # Создаем проект
            self.project_data = Project(
                id=self.project_id,
                name=project_config.get('name', 'Generated Project'),
                description=project_config.get('description', ''),
                workspace_path=str(self.workspace),
                user_id=self.user_id
            )
            
            logger.info(f"GPT-Pilot project created: {self.project_id}")
            
        except Exception as e:
            logger.error(f"Failed to create GPT-Pilot project: {e}")
            raise
    
    async def _initialize_orchestrator(self):
        """Инициализировать оркестратор GPT-Pilot"""
        try:
            Orchestrator = self.gpt_pilot_modules['Orchestrator']
            StateManager = self.gpt_pilot_modules['StateManager']
            
            # Создаем state manager
            self.state_manager = StateManager(self.project_data)
            
            # Создаем оркестратор
            self.orchestrator = Orchestrator(
                project=self.project_data,
                state_manager=self.state_manager
            )
            
            logger.info("GPT-Pilot orchestrator initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            raise
    
    async def _execute_generation(self, prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Выполнить генерацию кода"""
        try:
            # Запускаем генерацию через оркестратор
            result = await self.orchestrator.generate_code(
                prompt=prompt,
                context=context,
                project=self.project_data
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Code generation execution failed: {e}")
            raise