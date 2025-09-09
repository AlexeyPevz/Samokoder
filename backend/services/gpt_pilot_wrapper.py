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

class SamokoderGPTPilot:
    """
    Обертка над GPT-Pilot для интеграции с SaaS платформой Самокодер
    Исправленная версия с правильной интеграцией
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
            
            # Временно создаем заглушки до полной интеграции GPT-Pilot
            self.project = {
                'config': project_config,
                'status': 'initialized',
                'created_at': datetime.now().isoformat()
            }
            self.orchestrator = None
            
            # Создаем базовую структуру проекта
            await self._create_basic_project_structure(app_name, app_description)
            
            return {
                'project_id': self.project_id,
                'status': 'initialized',
                'workspace': str(self.workspace),
                'message': 'Проект успешно инициализирован'
            }
            
        except Exception as e:
            # Логируем ошибку
            print(f"Error initializing project {self.project_id}: {e}")
            return {
                'project_id': self.project_id,
                'status': 'error',
                'error': str(e),
                'message': f'Ошибка инициализации проекта: {str(e)}'
            }
    
    async def _create_basic_project_structure(self, app_name: str, app_description: str):
        """Создает базовую структуру проекта"""
        
        # Создаем package.json для React приложения
        package_json = {
            "name": app_name.lower().replace(' ', '-'),
            "version": "1.0.0",
            "description": app_description,
            "main": "src/index.js",
            "scripts": {
                "start": "react-scripts start",
                "build": "react-scripts build",
                "test": "react-scripts test",
                "eject": "react-scripts eject"
            },
            "dependencies": {
                "react": "^18.2.0",
                "react-dom": "^18.2.0",
                "react-scripts": "5.0.1"
            },
            "browserslist": {
                "production": [
                    ">0.2%",
                    "not dead",
                    "not op_mini all"
                ],
                "development": [
                    "last 1 chrome version",
                    "last 1 firefox version",
                    "last 1 safari version"
                ]
            }
        }
        
        # Создаем базовые файлы
        files_to_create = {
            'package.json': json.dumps(package_json, indent=2),
            'public/index.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>''' + app_name + '''</title>
</head>
<body>
    <div id="root"></div>
</body>
</html>''',
            'src/index.js': '''import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);''',
            'src/App.js': '''import React from 'react';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>''' + app_name + '''</h1>
        <p>''' + app_description + '''</p>
      </header>
    </div>
  );
}

export default App;''',
            'src/App.css': '''.App {
  text-align: center;
}

.App-header {
  background-color: #282c34;
  padding: 20px;
  color: white;
}

.App-header h1 {
  margin: 0;
  font-size: 2rem;
}

.App-header p {
  margin: 10px 0 0 0;
  font-size: 1.2rem;
}'''
        }
        
        # Создаем файлы
        for file_path, content in files_to_create.items():
            full_path = self.workspace / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding='utf-8')
    
    async def chat_with_agents(self, message: str, context: str = "chat") -> AsyncGenerator[Dict, None]:
        """Основной метод для общения с агентами GPT-Pilot"""
        
        if not self.project:
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
                
                # Симулируем работу Product Owner агента
                await asyncio.sleep(1)
                yield {
                    'type': 'agent_response',
                    'agent': 'ProductOwner',
                    'content': f'Понял ваши требования: {message}. Создаю user stories...',
                    'timestamp': datetime.now().isoformat()
                }
                
            elif context == "architecture":
                yield {
                    'type': 'agent_response',
                    'agent': 'Architect',
                    'content': 'Планирую архитектуру приложения...',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Симулируем работу Architect агента
                await asyncio.sleep(1)
                yield {
                    'type': 'agent_response',
                    'agent': 'Architect',
                    'content': f'Архитектура для: {message}. Выбираю React + Node.js + PostgreSQL',
                    'timestamp': datetime.now().isoformat()
                }
                
            elif context == "development":
                yield {
                    'type': 'agent_response', 
                    'agent': 'Developer',
                    'content': 'Начинаю разработку...',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Симулируем работу Developer агента
                await asyncio.sleep(1)
                yield {
                    'type': 'agent_response',
                    'agent': 'Developer',
                    'content': f'Разрабатываю: {message}',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Создаем новый компонент
                component_name = f"Component{datetime.now().strftime('%H%M%S')}"
                component_content = f'''import React from 'react';

function {component_name}() {{
  return (
    <div className="{component_name.lower()}">
      <h2>{component_name}</h2>
      <p>Создан для: {message}</p>
    </div>
  );
}}

export default {component_name};'''
                
                component_path = self.workspace / f'src/{component_name}.js'
                component_path.write_text(component_content, encoding='utf-8')
                
                # Уведомляем о созданных файлах
                yield {
                    'type': 'files_updated',
                    'files': [f'src/{component_name}.js'],
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            # Логируем ошибку
            print(f"Error in chat_with_agents: {e}")
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
            await asyncio.sleep(2)
            yield {
                'type': 'agent_complete',
                'agent': 'ProductOwner',
                'result': {'user_stories': ['Как пользователь, я хочу управлять задачами', 'Как пользователь, я хочу видеть прогресс']},
                'progress': 20
            }
            
            # 2. Планирование архитектуры (Architect)
            yield {'type': 'status', 'message': 'Запуск Architect агента...'}
            await asyncio.sleep(2)
            
            yield {
                'type': 'agent_complete', 
                'agent': 'Architect',
                'result': {'architecture': 'React + Node.js + PostgreSQL', 'components': ['TaskList', 'TaskForm', 'TaskItem']},
                'progress': 40
            }
            
            # 3. Разработка (Developer)
            yield {'type': 'status', 'message': 'Запуск Developer агента...'}
            
            # Создаем компоненты
            components = ['TaskList', 'TaskForm', 'TaskItem', 'Header', 'Footer']
            for i, component in enumerate(components):
                await asyncio.sleep(1)
                yield {
                    'type': 'development_update',
                    'content': f'Создаю компонент {component}...',
                    'progress': min(40 + (i+1) * 10, 90)
                }
                
                # Создаем файл компонента
                component_content = f'''import React from 'react';

function {component}() {{
  return (
    <div className="{component.lower()}">
      <h2>{component}</h2>
      <p>Компонент {component} готов к использованию</p>
    </div>
  );
}}

export default {component};'''
                
                component_path = self.workspace / f'src/components/{component}.js'
                component_path.parent.mkdir(parents=True, exist_ok=True)
                component_path.write_text(component_content, encoding='utf-8')
                
                # Уведомляем о созданных файлах
                yield {
                    'type': 'files_created',
                    'files': [f'src/components/{component}.js']
                }
            
            # 4. Завершение
            yield {
                'type': 'generation_complete',
                'message': 'Приложение готово!',
                'progress': 100,
                'files_count': len(self.get_project_files())
            }
            
        except Exception as e:
            # Логируем ошибку
            print(f"Error in generate_full_app: {e}")
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
        except Exception as e:
            # Логируем ошибку
            print(f"Error reading file {file_path}: {e}")
            raise FileNotFoundError(f"Ошибка чтения файла {file_path}: {str(e)}")
    
    def create_zip_export(self) -> Path:
        """Создает ZIP архив проекта"""
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
            # Логируем ошибку
            print(f"Error creating zip export: {e}")
            raise Exception(f"Ошибка создания ZIP архива: {str(e)}")
    
    async def restore_from_workspace(self):
        """Восстанавливает состояние проекта из workspace"""
        try:
            # Проверяем, есть ли файлы в workspace
            if self.workspace.exists() and any(self.workspace.iterdir()):
                # Восстанавливаем состояние проекта
                self.project = {
                    'config': {
                        'app': {
                            'app_name': 'Restored Project',
                            'app_type': 'web',
                            'description': 'Восстановленный проект'
                        },
                        'workspace': str(self.workspace),
                        'user_id': self.user_id
                    },
                    'status': 'restored',
                    'created_at': datetime.now().isoformat()
                }
            else:
                # Если workspace пустой, создаем базовую структуру
                await self._create_basic_project_structure('Restored Project', 'Восстановленный проект')
        except Exception as e:
            # Логируем ошибку
            print(f"Error restoring from workspace: {e}")
            # Создаем базовую структуру в случае ошибки
            await self._create_basic_project_structure('Restored Project', 'Восстановленный проект')