#!/usr/bin/env python3
"""
Упрощенный адаптер для интеграции с GPT-Pilot
Работает без полной интеграции с базой данных GPT-Pilot
"""

import asyncio
import os
import sys
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SamokoderGPTPilotSimpleAdapter:
    """
    Упрощенный адаптер для интеграции с GPT-Pilot
    Работает без полной интеграции с базой данных
    """
    
    def __init__(self, project_id: str, user_id: str, user_api_keys: Dict[str, str]):
        self.project_id = project_id
        self.user_id = user_id
        self.user_api_keys = user_api_keys
        
        # Настраиваем рабочую директорию
        self.workspace = Path(f"workspaces/{user_id}/{project_id}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Состояние проекта
        self.project_data = None
        self.initialized = False
        
        # Настройки API
        self.setup_api_config()
        
        logger.info(f"SamokoderGPTPilotSimpleAdapter initialized for project {project_id}")
    
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
                logger.warning("No API keys provided, using dummy keys")
                raise ValueError("API keys not configured. Please set OpenRouter, OpenAI, Anthropic, or Groq API key.")
                os.environ['MODEL_NAME'] = 'gpt-4o-mini'
                os.environ['ENDPOINT'] = 'OPENAI'
    
    async def initialize_project(self, app_name: str, app_description: str) -> Dict[str, Any]:
        """Инициализирует проект"""
        try:
            # Создаем данные проекта
            self.project_data = {
                'id': str(uuid.uuid4()),
                'name': app_name,
                'description': app_description,
                'created_at': datetime.now().isoformat(),
                'status': 'initialized'
            }
            
            # Создаем базовую структуру проекта
            await self._create_basic_project_structure(app_name, app_description)
            
            self.initialized = True
            
            logger.info(f"Project {self.project_id} initialized successfully")
            
            return {
                'project_id': self.project_data['id'],
                'status': 'initialized',
                'workspace': str(self.workspace),
                'message': 'Проект успешно инициализирован'
            }
            
        except Exception as e:
            logger.error(f"Error initializing project: {e}")
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
        
        # Создаем структуру директорий
        src_dir = self.workspace / "src"
        public_dir = self.workspace / "public"
        src_dir.mkdir(exist_ok=True)
        public_dir.mkdir(exist_ok=True)
        
        # Создаем файлы
        with open(self.workspace / "package.json", "w", encoding="utf-8") as f:
            json.dump(package_json, f, indent=2)
        
        # Создаем README.md
        readme_content = f"""# {app_name}

{app_description}

## Установка

```bash
npm install
```

## Запуск

```bash
npm start
```

## Сборка

```bash
npm run build
```
"""
        
        with open(self.workspace / "README.md", "w", encoding="utf-8") as f:
            f.write(readme_content)
        
        # Создаем базовый React компонент
        app_js_content = f"""import React from 'react';
import './App.css';

function App() {{
  return (
    <div className="App">
      <header className="App-header">
        <h1>{app_name}</h1>
        <p>{app_description}</p>
        <p>
          Редактируйте <code>src/App.js</code> и сохраните для перезагрузки.
        </p>
      </header>
    </div>
  );
}}

export default App;
"""
        
        with open(src_dir / "App.js", "w", encoding="utf-8") as f:
            f.write(app_js_content)
        
        # Создаем index.js
        index_js_content = """import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
"""
        
        with open(src_dir / "index.js", "w", encoding="utf-8") as f:
            f.write(index_js_content)
        
        # Создаем index.html
        index_html_content = f"""<!DOCTYPE html>
<html lang="ru">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <meta name="description" content="{app_description}" />
    <title>{app_name}</title>
  </head>
  <body>
    <noscript>Вам нужно включить JavaScript для запуска этого приложения.</noscript>
    <div id="root"></div>
  </body>
</html>
"""
        
        with open(public_dir / "index.html", "w", encoding="utf-8") as f:
            f.write(index_html_content)
    
    async def chat_with_agents(self, message: str, context: str = "chat") -> AsyncGenerator[Dict, None]:
        """Чат с агентами GPT-Pilot (симуляция)"""
        try:
            if not self.initialized:
                yield {
                    'type': 'error',
                    'message': 'Проект не инициализирован',
                    'timestamp': datetime.now().isoformat()
                }
                return
            
            # Симулируем работу агентов
            agents = [
                {'name': 'Product Owner', 'role': 'Анализ требований'},
                {'name': 'Architect', 'role': 'Проектирование архитектуры'},
                {'name': 'Developer', 'role': 'Разработка кода'},
                {'name': 'Tech Lead', 'role': 'Контроль качества'}
            ]
            
            yield {
                'type': 'status',
                'message': 'Агенты анализируют запрос...',
                'timestamp': datetime.now().isoformat()
            }
            
            await asyncio.sleep(0.5)
            
            for agent in agents:
                yield {
                    'type': 'agent_response',
                    'agent': agent['name'],
                    'message': f'{agent["role"]}: {message}',
                    'timestamp': datetime.now().isoformat()
                }
                await asyncio.sleep(0.5)
            
            yield {
                'type': 'completion',
                'message': 'Агенты завершили анализ',
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
        """Полная генерация приложения (симуляция)"""
        try:
            if not self.initialized:
                yield {
                    'type': 'error',
                    'message': 'Проект не инициализирован',
                    'timestamp': datetime.now().isoformat()
                }
                return
            
            # Симулируем процесс генерации
            steps = [
                "Инициализация проекта...",
                "Создание структуры файлов...",
                "Генерация компонентов...",
                "Настройка зависимостей...",
                "Создание документации...",
                "Финальная проверка..."
            ]
            
            for i, step in enumerate(steps):
                progress = int((i + 1) / len(steps) * 100)
                yield {
                    'type': 'progress',
                    'message': step,
                    'progress': progress,
                    'timestamp': datetime.now().isoformat()
                }
                await asyncio.sleep(1)
            
            yield {
                'type': 'completion',
                'message': 'Приложение готово!',
                'progress': 100,
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
        if not self.workspace.exists():
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
                self.project_data = {
                    'id': str(uuid.uuid4()),
                    'name': 'Restored Project',
                    'description': 'Восстановленный проект',
                    'created_at': datetime.now().isoformat(),
                    'status': 'restored'
                }
                self.initialized = True
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
            'initialized': self.initialized,
            'project': self.project_data,
            'status': 'active' if self.initialized else 'inactive'
        }