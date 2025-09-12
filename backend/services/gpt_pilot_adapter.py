#!/usr/bin/env python3
"""
Адаптер для интеграции с GPT-Pilot
Обеспечивает полную интеграцию с GPT-Pilot core
"""

import asyncio
import os
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator, Any
from datetime import datetime
import logging

# Правильные импорты GPT-Pilot через модуль интеграции
from backend.integrations.gpt_pilot.imports import get_gpt_pilot_modules, is_gpt_pilot_available

logger = logging.getLogger(__name__)

class SamokoderGPTPilotAdapter:
    """
    Полноценный адаптер для интеграции с GPT-Pilot
    Обеспечивает все функции GPT-Pilot через наш API
    """
    
    def __init__(self, project_id: str, user_id: str, user_api_keys: Dict[str, str]):
        self.project_id = project_id
        self.user_id = user_id
        self.user_api_keys = user_api_keys
        
        # Проверяем доступность GPT-Pilot
        self.gpt_pilot_modules = get_gpt_pilot_modules()
        if not is_gpt_pilot_available():
            raise RuntimeError(f"GPT-Pilot not available: {self.gpt_pilot_modules.get('error', 'Unknown error')}")
        
        # Настраиваем рабочую директорию
        self.workspace = Path(f"workspaces/{user_id}/{project_id}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Компоненты GPT-Pilot (типизированные)
        self.project: Optional[Any] = None
        self.branch: Optional[Any] = None
        self.orchestrator: Optional[Any] = None
        self.state_manager: Optional[Any] = None
        self.vfs: Optional[Any] = None
        
        # Настройки
        self.user_settings: Optional[Any] = None
        
        # Настройки API
        self.setup_api_config()
    
    def setup_api_config(self):
        """Настраивает API ключи из пользовательских BYOK"""
        
        # Приоритет: пользовательские ключи > системные fallback
        if 'openrouter' in self.user_api_keys:
            os.environ['OPENROUTER_API_KEY'] = self.user_api_keys['openrouter']
            os.environ['MODEL_NAME'] = 'deepseek/deepseek-v3'  # Бесплатная модель
            os.environ['ENDPOINT'] = 'OPENROUTER'
        elif 'openai' in self.user_api_keys:
            os.environ['OPENAI_API_KEY'] = self.user_api_keys['openai']
            os.environ['MODEL_NAME'] = 'gpt-4o-mini'
            os.environ['ENDPOINT'] = 'OPENAI'
        elif 'anthropic' in self.user_api_keys:
            os.environ['ANTHROPIC_API_KEY'] = self.user_api_keys['anthropic']
            os.environ['MODEL_NAME'] = 'claude-3-haiku-20240307'
            os.environ['ENDPOINT'] = 'ANTHROPIC'
        elif 'groq' in self.user_api_keys:
            os.environ['GROQ_API_KEY'] = self.user_api_keys['groq']
            os.environ['MODEL_NAME'] = 'llama-3.1-70b-versatile'
            os.environ['ENDPOINT'] = 'GROQ'
        else:
            # Fallback на системные ключи
            if os.getenv('SYSTEM_OPENROUTER_KEY'):
                os.environ['OPENROUTER_API_KEY'] = os.getenv('SYSTEM_OPENROUTER_KEY')
                os.environ['MODEL_NAME'] = 'deepseek/deepseek-v3'
                os.environ['ENDPOINT'] = 'OPENROUTER'
            elif os.getenv('SYSTEM_OPENAI_KEY'):
                os.environ['OPENAI_API_KEY'] = os.getenv('SYSTEM_OPENAI_KEY')
                os.environ['MODEL_NAME'] = 'gpt-4o-mini'
                os.environ['ENDPOINT'] = 'OPENAI'
            else:
                logger.error("No API keys provided. Please configure API keys before using GPT-Pilot.")
                raise ValueError("API keys not configured. Please set OpenRouter, OpenAI, Anthropic, or Groq API key.")
    
    async def initialize_project(self, app_name: str, app_description: str) -> Dict[str, Any]:
        """Инициализирует проект в GPT-Pilot"""
        try:
            # Получаем классы из модулей
            UserSettings = self.gpt_pilot_modules['UserSettings']
            VFS = self.gpt_pilot_modules['VFS']
            
            # Создаем настройки пользователя
            self.user_settings = UserSettings()
            
            # Создаем VFS для работы с файлами
            self.vfs = VFS(self.workspace)
            
            # Получаем классы из модулей
            get_session = self.gpt_pilot_modules['get_session']
            Project = self.gpt_pilot_modules['Project']
            Branch = self.gpt_pilot_modules['Branch']
            StateManager = self.gpt_pilot_modules['StateManager']
            Orchestrator = self.gpt_pilot_modules['Orchestrator']
            
            # Создаем проект в GPT-Pilot
            async with get_session() as session:
                # Создаем проект
                self.project = Project(
                    name=app_name,
                    folder_name=app_name.lower().replace(' ', '-')
                )
                session.add(self.project)
                await session.commit()
                await session.refresh(self.project)
                
                # Создаем ветку
                self.branch = Branch(
                    project_id=self.project.id,
                    name="main"
                )
                session.add(self.branch)
                await session.commit()
                await session.refresh(self.branch)
                
                # Создаем StateManager
                self.state_manager = StateManager(self.branch)
                
                # Создаем Orchestrator
                self.orchestrator = Orchestrator(
                    branch=self.branch,
                    state_manager=self.state_manager,
                    vfs=self.vfs
                )
                
                logger.info(f"Project {self.project.id} initialized successfully")
                
                return {
                    'project_id': str(self.project.id),
                    'status': 'initialized',
                    'workspace': str(self.workspace),
                    'message': 'Проект успешно инициализирован в GPT-Pilot'
                }
                
        except Exception as e:
            logger.error(f"Error initializing project: {e}")
            return {
                'project_id': self.project_id,
                'status': 'error',
                'error': str(e),
                'message': f'Ошибка инициализации проекта: {str(e)}'
            }
    
    async def chat_with_agents(self, message: str, context: str = "chat") -> AsyncGenerator[Dict, None]:
        """Чат с агентами GPT-Pilot"""
        try:
            if not self.orchestrator:
                yield {
                    'type': 'error',
                    'message': 'Проект не инициализирован',
                    'timestamp': datetime.now().isoformat()
                }
                return
            
            # Добавляем сообщение в состояние
            await self.state_manager.add_user_message(message)
            
            # Запускаем оркестратор
            yield {
                'type': 'status',
                'message': 'Агенты анализируют запрос...',
                'timestamp': datetime.now().isoformat()
            }
            
            # Запускаем оркестратор в отдельной задаче
            orchestrator_task = asyncio.create_task(self.orchestrator.run())
            
            # Мониторим прогресс
            while not orchestrator_task.done():
                await asyncio.sleep(0.5)
                
                # Получаем текущее состояние
                current_state = await self.state_manager.get_current_state()
                
                if current_state:
                    yield {
                        'type': 'progress',
                        'message': f'Агент {current_state.get("current_agent", "unknown")} работает...',
                        'progress': current_state.get('progress', 0),
                        'timestamp': datetime.now().isoformat()
                    }
            
            # Получаем результат
            result = await orchestrator_task
            
            if result:
                yield {
                    'type': 'completion',
                    'message': 'Агенты завершили работу',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                yield {
                    'type': 'error',
                    'message': 'Ошибка в работе агентов',
                    'timestamp': datetime.now().isoformat()
                }
                
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
            if not self.orchestrator:
                yield {
                    'type': 'error',
                    'message': 'Проект не инициализирован',
                    'timestamp': datetime.now().isoformat()
                }
                return
            
            # Добавляем задачу генерации
            await self.state_manager.add_user_message("Создай полноценное приложение согласно техническому заданию")
            
            yield {
                'type': 'status',
                'message': 'Начинаем генерацию приложения...',
                'progress': 0,
                'timestamp': datetime.now().isoformat()
            }
            
            # Запускаем оркестратор
            orchestrator_task = asyncio.create_task(self.orchestrator.run())
            
            # Мониторим прогресс
            progress = 0
            while not orchestrator_task.done():
                await asyncio.sleep(1)
                progress = min(progress + 10, 90)
                
                yield {
                    'type': 'progress',
                    'message': 'Генерируем приложение...',
                    'progress': progress,
                    'timestamp': datetime.now().isoformat()
                }
            
            # Получаем результат
            result = await orchestrator_task
            
            if result:
                yield {
                    'type': 'completion',
                    'message': 'Приложение готово!',
                    'progress': 100,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                yield {
                    'type': 'error',
                    'message': 'Ошибка генерации приложения',
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error in generate_full_app: {e}")
            yield {
                'type': 'error',
                'message': f'Ошибка генерации: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def get_project_files(self) -> Dict:
        """Возвращает структуру файлов проекта"""
        if not self.vfs:
            return {}
        
        def scan_directory(path: Path, base_path: Path) -> Dict:
            result = {}
            try:
                for item in path.iterdir():
                    if item.is_file():
                        result[item.name] = {
                            "type": "file",
                            "size": item.stat().st_size,
                            "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                        }
                    elif item.is_dir() and not item.name.startswith('.'):
                        result[item.name] = scan_directory(item, base_path)
            except PermissionError:
                pass
            return result
        
        return scan_directory(self.workspace, self.workspace)
    
    def get_file_content(self, file_path: str) -> str:
        """Получает содержимое файла"""
        full_path = self.workspace / file_path
        
        if not full_path.exists() or not full_path.is_file():
            raise FileNotFoundError(f"Файл {file_path} не найден")
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            return f"[Бинарный файл: {full_path.name}, размер: {full_path.stat().st_size} байт]"
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            raise FileNotFoundError(f"Ошибка чтения файла {file_path}: {str(e)}")
    
    def create_zip_export(self) -> Path:
        """Создает ZIP архив проекта"""
        import zipfile
        from datetime import datetime
        
        export_path = Path("exports") / self.user_id
        export_path.mkdir(parents=True, exist_ok=True)
        
        zip_filename = f"{self.project_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = export_path / zip_filename
        
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in self.workspace.rglob('*'):
                    if file_path.is_file() and not any(exclude in str(file_path) for exclude in ['.git', 'node_modules', '__pycache__']):
                        arcname = file_path.relative_to(self.workspace)
                        zipf.write(file_path, arcname)
            
            return zip_path
        except Exception as e:
            logger.error(f"Error creating zip export: {e}")
            raise Exception(f"Ошибка создания ZIP архива: {str(e)}")
    
    async def restore_from_workspace(self):
        """Восстанавливает состояние проекта из workspace"""
        try:
            # Проверяем, есть ли файлы в workspace
            if self.workspace.exists() and any(self.workspace.iterdir()):
                # Восстанавливаем состояние проекта
                await self.initialize_project('Restored Project', 'Восстановленный проект')
            else:
                # Если workspace пустой, создаем базовую структуру
                await self.initialize_project('New Project', 'Новый проект')
        except Exception as e:
            logger.error(f"Error restoring from workspace: {e}")
            # Создаем базовую структуру в случае ошибки
            await self.initialize_project('New Project', 'Новый проект')
    
    def get_project_status(self) -> Dict[str, Any]:
        """Возвращает статус проекта"""
        return {
            'project_id': self.project_id,
            'user_id': self.user_id,
            'workspace': str(self.workspace),
            'initialized': self.orchestrator is not None,
            'project': {
                'id': str(self.project.id) if self.project else None,
                'name': self.project.name if self.project else None,
                'created_at': self.project.created_at.isoformat() if self.project else None
            } if self.project else None,
            'branch': {
                'id': str(self.branch.id) if self.branch else None,
                'name': self.branch.name if self.branch else None
            } if self.branch else None,
            'status': 'active' if self.orchestrator else 'inactive'
        }