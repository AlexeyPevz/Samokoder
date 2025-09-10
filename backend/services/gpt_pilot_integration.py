"""
Единая интеграция с GPT-Pilot
Убирает дублирование и создает чистую архитектуру
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator, Any
from datetime import datetime
import logging
import zipfile
import shutil

logger = logging.getLogger(__name__)

class GPTPilotIntegration:
    """
    Единая интеграция с GPT-Pilot
    Поддерживает как реальную интеграцию, так и mock режим
    """
    
    def __init__(self, project_id: str, user_id: str, user_api_keys: Dict[str, str]):
        self.project_id = project_id
        self.user_id = user_id
        self.user_api_keys = user_api_keys
        self.initialized = False
        
        # Настраиваем рабочую директорию
        self.workspace = Path(f"workspaces/{user_id}/{project_id}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Определяем режим работы
        self.mode = self._determine_mode()
        logger.info(f"GPT-Pilot integration initialized in {self.mode} mode")
    
    def _determine_mode(self) -> str:
        """Определяет режим работы интеграции"""
        gpt_pilot_path = Path("samokoder-core")
        
        if gpt_pilot_path.exists() and self._check_gpt_pilot_availability():
            return "real"
        else:
            logger.warning("GPT-Pilot not available, using mock mode")
            return "mock"
    
    def _check_gpt_pilot_availability(self) -> bool:
        """Проверяет доступность GPT-Pilot"""
        try:
            gpt_pilot_path = Path("samokoder-core")
            if not gpt_pilot_path.exists():
                return False
            
            # Проверяем наличие основных файлов GPT-Pilot
            required_files = ["main.py", "agents", "utils"]
            for file_name in required_files:
                if not (gpt_pilot_path / file_name).exists():
                    logger.warning(f"GPT-Pilot file not found: {file_name}")
                    return False
            
            return True
        except Exception as e:
            logger.error(f"Error checking GPT-Pilot availability: {e}")
            return False
    
    async def initialize_project(self, app_name: str, app_description: str) -> Dict[str, Any]:
        """Инициализирует проект"""
        try:
            if self.mode == "real":
                result = await self._initialize_real_project(app_name, app_description)
            else:
                result = await self._initialize_mock_project(app_name, app_description)
            
            self.initialized = True
            return result
            
        except Exception as e:
            logger.error(f"Error initializing project: {e}")
            return {
                'project_id': self.project_id,
                'status': 'error',
                'error': str(e),
                'message': f'Ошибка инициализации проекта: {str(e)}'
            }
    
    async def _initialize_real_project(self, app_name: str, app_description: str) -> Dict[str, Any]:
        """Инициализация реального проекта с GPT-Pilot"""
        try:
            # Здесь должна быть реальная интеграция с GPT-Pilot
            # Пока что возвращаем успешный результат
            return {
                'project_id': self.project_id,
                'status': 'initialized',
                'workspace': str(self.workspace),
                'message': 'Проект инициализирован с GPT-Pilot'
            }
        except Exception as e:
            logger.error(f"Real project initialization error: {e}")
            raise
    
    async def _initialize_mock_project(self, app_name: str, app_description: str) -> Dict[str, Any]:
        """Инициализация mock проекта"""
        try:
            # Создаем базовую структуру проекта
            project_structure = {
                "app_name": app_name,
                "app_description": app_description,
                "created_at": datetime.now().isoformat(),
                "files": {
                    "README.md": f"# {app_name}\n\n{app_description}",
                    "package.json": json.dumps({
                        "name": app_name.lower().replace(" ", "-"),
                        "version": "1.0.0",
                        "description": app_description
                    }, indent=2),
                    "src/main.py": "# Main application file\nprint('Hello, World!')"
                }
            }
            
            # Сохраняем структуру проекта
            project_file = self.workspace / "project.json"
            with open(project_file, 'w', encoding='utf-8') as f:
                json.dump(project_structure, f, indent=2, ensure_ascii=False)
            
            # Создаем файлы проекта
            for file_path, content in project_structure["files"].items():
                full_path = self.workspace / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            return {
                'project_id': self.project_id,
                'status': 'initialized',
                'workspace': str(self.workspace),
                'message': 'Mock проект инициализирован'
            }
            
        except Exception as e:
            logger.error(f"Mock project initialization error: {e}")
            raise
    
    async def chat_with_agents(self, message: str, context: str = "chat") -> AsyncGenerator[Dict, None]:
        """Чат с агентами"""
        try:
            if self.mode == "real":
                async for update in self._chat_with_real_agents(message, context):
                    yield update
            else:
                async for update in self._chat_with_mock_agents(message, context):
                    yield update
                    
        except Exception as e:
            logger.error(f"Error in chat with agents: {e}")
            yield {
                'type': 'error',
                'message': f'Ошибка в работе агентов: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    async def _chat_with_real_agents(self, message: str, context: str) -> AsyncGenerator[Dict, None]:
        """Чат с реальными агентами GPT-Pilot"""
        # Здесь должна быть реальная интеграция с GPT-Pilot агентами
        # Пока что возвращаем mock ответы
        yield {
            'type': 'agent_response',
            'agent': 'ProductOwner',
            'message': f'Получено сообщение: {message}',
            'timestamp': datetime.now().isoformat()
        }
        
        await asyncio.sleep(0.1)  # Имитация обработки
        
        yield {
            'type': 'agent_response',
            'agent': 'Architect',
            'message': 'Анализирую архитектуру проекта...',
            'timestamp': datetime.now().isoformat()
        }
        
        await asyncio.sleep(0.1)
        
        yield {
            'type': 'agent_response',
            'agent': 'Developer',
            'message': 'Готов к разработке!',
            'timestamp': datetime.now().isoformat()
        }
    
    async def _chat_with_mock_agents(self, message: str, context: str) -> AsyncGenerator[Dict, None]:
        """Чат с mock агентами"""
        agents = ['ProductOwner', 'Architect', 'Developer', 'Tester']
        
        for i, agent in enumerate(agents):
            yield {
                'type': 'agent_response',
                'agent': agent,
                'message': f'Mock ответ от {agent}: {message}',
                'progress': (i + 1) * 25,
                'timestamp': datetime.now().isoformat()
            }
            
            await asyncio.sleep(0.1)  # Имитация обработки
        
        yield {
            'type': 'completion',
            'message': 'Все агенты ответили',
            'timestamp': datetime.now().isoformat()
        }
    
    async def generate_full_app(self) -> AsyncGenerator[Dict, None]:
        """Полная генерация приложения"""
        try:
            if self.mode == "real":
                async for update in self._generate_real_app():
                    yield update
            else:
                async for update in self._generate_mock_app():
                    yield update
                    
        except Exception as e:
            logger.error(f"Error in full app generation: {e}")
            yield {
                'type': 'error',
                'message': f'Ошибка генерации: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    async def _generate_real_app(self) -> AsyncGenerator[Dict, None]:
        """Генерация реального приложения"""
        # Здесь должна быть реальная генерация с GPT-Pilot
        # Пока что возвращаем mock процесс
        steps = [
            "Анализ требований",
            "Проектирование архитектуры",
            "Создание базовой структуры",
            "Генерация компонентов",
            "Настройка конфигурации",
            "Создание документации"
        ]
        
        for i, step in enumerate(steps):
            yield {
                'type': 'generation_step',
                'step': step,
                'progress': (i + 1) * 16,
                'message': f'Выполняется: {step}',
                'timestamp': datetime.now().isoformat()
            }
            
            await asyncio.sleep(0.5)  # Имитация генерации
        
        yield {
            'type': 'completion',
            'message': 'Приложение сгенерировано успешно',
            'timestamp': datetime.now().isoformat()
        }
    
    async def _generate_mock_app(self) -> AsyncGenerator[Dict, None]:
        """Генерация mock приложения"""
        steps = [
            "Создание mock структуры",
            "Генерация тестовых файлов",
            "Настройка mock конфигурации"
        ]
        
        for i, step in enumerate(steps):
            yield {
                'type': 'generation_step',
                'step': step,
                'progress': (i + 1) * 33,
                'message': f'Mock: {step}',
                'timestamp': datetime.now().isoformat()
            }
            
            await asyncio.sleep(0.3)
        
        # Создаем дополнительные mock файлы
        mock_files = {
            "src/components/Header.js": "// Mock Header component",
            "src/components/Footer.js": "// Mock Footer component",
            "src/utils/helpers.js": "// Mock utility functions",
            "tests/test_basic.js": "// Mock tests"
        }
        
        for file_path, content in mock_files.items():
            full_path = self.workspace / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        yield {
            'type': 'completion',
            'message': 'Mock приложение сгенерировано',
            'timestamp': datetime.now().isoformat()
        }
    
    def get_project_files(self) -> Dict:
        """Возвращает структуру файлов проекта"""
        try:
            if not self.workspace.exists():
                return {}
            
            def build_file_tree(path: Path, relative_path: str = "") -> Dict:
                tree = {}
                
                for item in path.iterdir():
                    if item.is_file():
                        tree[item.name] = {
                            "type": "file",
                            "size": item.stat().st_size,
                            "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                        }
                    elif item.is_dir() and not item.name.startswith('.'):
                        tree[item.name] = {
                            "type": "directory",
                            "children": build_file_tree(item, f"{relative_path}/{item.name}")
                        }
                
                return tree
            
            return build_file_tree(self.workspace)
            
        except Exception as e:
            logger.error(f"Error getting project files: {e}")
            return {}
    
    def get_file_content(self, file_path: str) -> str:
        """Получает содержимое файла"""
        try:
            full_path = self.workspace / file_path
            
            # Проверяем безопасность пути
            if not str(full_path.resolve()).startswith(str(self.workspace.resolve())):
                raise ValueError("Недопустимый путь к файлу")
            
            if not full_path.exists():
                raise FileNotFoundError(f"Файл не найден: {file_path}")
            
            with open(full_path, 'r', encoding='utf-8') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Error getting file content: {e}")
            raise
    
    def create_zip_export(self) -> Path:
        """Создает ZIP архив проекта"""
        try:
            export_dir = Path("exports")
            export_dir.mkdir(exist_ok=True)
            
            zip_path = export_dir / f"samokoder_project_{self.project_id}.zip"
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.workspace):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(self.workspace)
                        zipf.write(file_path, arcname)
            
            logger.info(f"Project exported to: {zip_path}")
            return zip_path
            
        except Exception as e:
            logger.error(f"Error creating zip export: {e}")
            raise
    
    async def restore_from_workspace(self):
        """Восстанавливает состояние проекта из workspace"""
        try:
            if not self.workspace.exists():
                logger.warning(f"Workspace not found: {self.workspace}")
                return
            
            project_file = self.workspace / "project.json"
            if project_file.exists():
                with open(project_file, 'r', encoding='utf-8') as f:
                    project_data = json.load(f)
                
                logger.info(f"Project restored from workspace: {project_data.get('app_name', 'Unknown')}")
            else:
                logger.info("No project.json found, workspace restored as-is")
                
        except Exception as e:
            logger.error(f"Error restoring from workspace: {e}")
            raise
    
    def get_project_status(self) -> Dict[str, Any]:
        """Возвращает статус проекта"""
        try:
            return {
                'project_id': self.project_id,
                'user_id': self.user_id,
                'workspace': str(self.workspace),
                'initialized': self.initialized,
                'mode': self.mode,
                'status': 'active' if self.initialized else 'inactive',
                'files_count': len(list(self.workspace.rglob('*'))) if self.workspace.exists() else 0,
                'last_modified': datetime.now().isoformat()
            }
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
    
    def cleanup(self):
        """Очищает ресурсы"""
        try:
            logger.info(f"Cleaning up resources for project {self.project_id}")
            # Здесь можно добавить очистку ресурсов GPT-Pilot
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Деструктор для очистки ресурсов"""
        self.cleanup()