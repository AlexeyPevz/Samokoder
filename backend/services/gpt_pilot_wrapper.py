import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator
from datetime import datetime
import zipfile

# Добавляем путь к GPT-Pilot в sys.path
sys.path.append(str(Path(__file__).parent.parent.parent / "samokoder-core"))

from core.agents.orchestrator import Orchestrator
from core.db.models.project import Project
from core.config.user_settings import UserSettings
from core.llm.openai_client import OpenAIClient
from core.llm.anthropic_client import AnthropicClient
from core.llm.groq_client import GroqClient

class SamokoderGPTPilot:
    """
    Обертка над GPT-Pilot для интеграции с SaaS платформой Самокодер
    """
    
    def __init__(self, project_id: str, user_id: str, user_api_keys: Dict[str, str]):
        self.project_id = project_id
        self.user_id = user_id
        self.user_api_keys = user_api_keys
        
        # Настраиваем рабочую директорию
        self.workspace = Path(f"workspaces/{user_id}/{project_id}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Инициализируем компоненты GPT-Pilot
        self.project = None
        self.orchestrator = None
        
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
            os.environ['MODEL_NAME'] = 'llama-3-8b-8192'
            os.environ['ENDPOINT'] = 'GROQ'
        else:
            # Fallback на системные ключи для бесплатных моделей
            os.environ['OPENROUTER_API_KEY'] = os.getenv('SYSTEM_OPENROUTER_KEY')
            os.environ['MODEL_NAME'] = 'deepseek/deepseek-v3'
            os.environ['ENDPOINT'] = 'OPENROUTER'
    
    async def initialize_project(self, app_description: str, app_name: str):
        """Инициализирует новый проект через GPT-Pilot"""
        
        try:
            # Создаем конфиг проекта для GPT-Pilot
            project_config = {
                'app': {
                    'app_name': app_name,
                    'app_type': 'web',
                    'description': app_description
                },
                'workspace': str(self.workspace),
                'user_id': self.user_id
            }
            
            # Создаем объект проекта GPT-Pilot
            self.project = Project(project_config)
            
            # Инициализируем оркестратор
            self.orchestrator = Orchestrator(self.project)
            
            return {
                'project_id': self.project_id,
                'status': 'initialized',
                'workspace': str(self.workspace),
                'message': 'Проект успешно инициализирован'
            }
            
        except Exception as e:
            return {
                'project_id': self.project_id,
                'status': 'error',
                'error': str(e),
                'message': f'Ошибка инициализации проекта: {str(e)}'
            }
    
    async def chat_with_agents(self, message: str, context: str = "chat") -> AsyncGenerator[Dict, None]:
        """Основной метод для общения с агентами GPT-Pilot"""
        
        if not self.project or not self.orchestrator:
            yield {
                'type': 'error',
                'message': 'Проект не инициализирован',
                'timestamp': datetime.now().isoformat()
            }
            return
        
        try:
            # В зависимости от контекста, вызываем нужного агента
            if context == "requirements":
                yield {
                    'type': 'agent_response',
                    'agent': 'ProductOwner', 
                    'content': 'Анализирую требования к приложению...',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Здесь будет вызов агента Product Owner
                # Пока возвращаем заглушку
                yield {
                    'type': 'agent_response',
                    'agent': 'ProductOwner',
                    'content': f'Понял ваши требования: {message}',
                    'timestamp': datetime.now().isoformat()
                }
                
            elif context == "architecture":
                yield {
                    'type': 'agent_response',
                    'agent': 'Architect',
                    'content': 'Планирую архитектуру приложения...',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Здесь будет вызов агента Architect
                yield {
                    'type': 'agent_response',
                    'agent': 'Architect',
                    'content': f'Архитектура для: {message}',
                    'timestamp': datetime.now().isoformat()
                }
                
            elif context == "development":
                yield {
                    'type': 'agent_response', 
                    'agent': 'Developer',
                    'content': 'Начинаю разработку...',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Здесь будет вызов агента Developer
                yield {
                    'type': 'agent_response',
                    'agent': 'Developer',
                    'content': f'Разрабатываю: {message}',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Если агент создал файлы, уведомляем об этом
                yield {
                    'type': 'files_updated',
                    'files': ['src/App.js', 'package.json'],
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            yield {
                'type': 'error',
                'message': f'Ошибка в работе агентов: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    async def generate_full_app(self) -> AsyncGenerator[Dict, None]:
        """Полная генерация приложения от начала до конца"""
        
        try:
            yield {'type': 'status', 'message': 'Запуск Product Owner агента...'}
            
            # 1. Анализ требований (Product Owner)
            yield {
                'type': 'agent_complete',
                'agent': 'ProductOwner',
                'result': {'user_stories': ['Как пользователь, я хочу...']},
                'progress': 20
            }
            
            # 2. Планирование архитектуры (Architect)
            yield {'type': 'status', 'message': 'Запуск Architect агента...'}
            
            yield {
                'type': 'agent_complete', 
                'agent': 'Architect',
                'result': {'architecture': 'React + Node.js + PostgreSQL'},
                'progress': 40
            }
            
            # 3. Разработка (Developer)
            yield {'type': 'status', 'message': 'Запуск Developer агента...'}
            
            # Симулируем разработку
            for i in range(5):
                await asyncio.sleep(1)  # Симуляция работы
                yield {
                    'type': 'development_update',
                    'content': f'Создаю файл {i+1}/5...',
                    'progress': min(40 + (i+1) * 10, 90)
                }
                
                # Уведомляем о созданных файлах
                yield {
                    'type': 'files_created',
                    'files': [f'src/component{i+1}.js']
                }
            
            # 4. Завершение
            yield {
                'type': 'generation_complete',
                'message': 'Приложение готово!',
                'progress': 100,
                'files_count': len(self.get_project_files())
            }
            
        except Exception as e:
            yield {
                'type': 'error',
                'message': f'Ошибка генерации: {str(e)}',
                'error': str(e)
            }
    
    def get_project_files(self) -> Dict:
        """Возвращает структуру файлов проекта"""
        
        def scan_directory(path: Path, base_path: Path) -> Dict:
            items = {}
            
            try:
                for item in path.iterdir():
                    if item.name.startswith('.') or item.name in ['node_modules', '__pycache__']:
                        continue
                    
                    relative_path = str(item.relative_to(base_path))
                    
                    if item.is_dir():
                        items[item.name] = {
                            'type': 'directory',
                            'path': relative_path,
                            'children': scan_directory(item, base_path)
                        }
                    else:
                        items[item.name] = {
                            'type': 'file',
                            'path': relative_path,
                            'size': item.stat().st_size,
                            'extension': item.suffix,
                            'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                        }
            except PermissionError:
                # Если нет доступа к директории
                pass
            
            return items
        
        return scan_directory(self.workspace, self.workspace)
    
    def get_file_content(self, file_path: str) -> str:
        """Возвращает содержимое файла"""
        full_path = self.workspace / file_path
        
        if not full_path.exists() or not full_path.is_file():
            raise FileNotFoundError(f"Файл {file_path} не найден")
        
        # Проверяем, что файл текстовый
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Если бинарный файл, возвращаем info
            return f"[Бинарный файл: {full_path.name}, размер: {full_path.stat().st_size} байт]"
    
    def create_zip_export(self) -> Path:
        """Создает ZIP архив проекта"""
        export_path = Path("exports") / self.user_id
        export_path.mkdir(parents=True, exist_ok=True)
        
        zip_filename = f"{self.project_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = export_path / zip_filename
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self.workspace.rglob('*'):
                if file_path.is_file() and not any(exclude in str(file_path) for exclude in ['.git', 'node_modules', '__pycache__']):
                    arcname = file_path.relative_to(self.workspace)
                    zipf.write(file_path, arcname)
        
        return zip_path
    
    async def restore_from_workspace(self):
        """Восстанавливает состояние проекта из workspace"""
        # Здесь будет логика восстановления состояния проекта
        # из существующих файлов в workspace
        pass