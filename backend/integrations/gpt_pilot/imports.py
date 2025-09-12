"""
GPT-Pilot Imports Module
Централизованные импорты GPT-Pilot БЕЗ sys.path manipulation
"""

import logging
from pathlib import Path
from typing import Optional, Any, Dict
import importlib.util
import sys

logger = logging.getLogger(__name__)

# Путь к GPT-Pilot core
GPT_PILOT_CORE_PATH = Path(__file__).parent.parent.parent.parent / "samokoder-core"

def _load_module_from_path(module_name: str, file_path: Path) -> Optional[Any]:
    """Загружает модуль из файла без изменения sys.path"""
    try:
        if not file_path.exists():
            return None
            
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            return None
            
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        logger.debug(f"Failed to load {module_name} from {file_path}: {e}")
        return None

def _find_gpt_pilot_file(module_path: str) -> Optional[Path]:
    """Находит файл модуля GPT-Pilot"""
    base_path = GPT_PILOT_CORE_PATH
    file_path = base_path / f"{module_path.replace('.', '/')}.py"
    
    if file_path.exists():
        return file_path
    
    # Попробуем найти в подпапках
    for py_file in base_path.rglob(f"{module_path.split('.')[-1]}.py"):
        if py_file.is_file():
            return py_file
    
    return None

def safe_import_gpt_pilot() -> Dict[str, Any]:
    """Безопасный импорт GPT-Pilot модулей БЕЗ sys.path manipulation"""
    if not GPT_PILOT_CORE_PATH.exists():
        logger.warning(f"GPT-Pilot core directory not found: {GPT_PILOT_CORE_PATH}")
        return _create_fallback_modules("GPT-Pilot core directory not found")
    
    try:
        # Загружаем модули по одному без изменения sys.path
        modules = {}
        
        # Project model
        project_file = _find_gpt_pilot_file("core.db.models.project")
        if project_file:
            project_module = _load_module_from_path("gpt_pilot_project", project_file)
            modules['Project'] = getattr(project_module, 'Project', None) if project_module else None
        else:
            modules['Project'] = None
            
        # Branch model  
        branch_file = _find_gpt_pilot_file("core.db.models.branch")
        if branch_file:
            branch_module = _load_module_from_path("gpt_pilot_branch", branch_file)
            modules['Branch'] = getattr(branch_module, 'Branch', None) if branch_module else None
        else:
            modules['Branch'] = None
            
        # UserSettings
        settings_file = _find_gpt_pilot_file("core.config.user_settings")
        if settings_file:
            settings_module = _load_module_from_path("gpt_pilot_settings", settings_file)
            modules['UserSettings'] = getattr(settings_module, 'UserSettings', None) if settings_module else None
        else:
            modules['UserSettings'] = None
            
        # Orchestrator
        orchestrator_file = _find_gpt_pilot_file("core.agents.orchestrator")
        if orchestrator_file:
            orchestrator_module = _load_module_from_path("gpt_pilot_orchestrator", orchestrator_file)
            modules['Orchestrator'] = getattr(orchestrator_module, 'Orchestrator', None) if orchestrator_module else None
        else:
            modules['Orchestrator'] = None
            
        # Session
        session_file = _find_gpt_pilot_file("core.db.session")
        if session_file:
            session_module = _load_module_from_path("gpt_pilot_session", session_file)
            modules['get_session'] = getattr(session_module, 'get_session', None) if session_module else None
        else:
            modules['get_session'] = None
            
        # StateManager
        state_file = _find_gpt_pilot_file("core.state.state_manager")
        if state_file:
            state_module = _load_module_from_path("gpt_pilot_state", state_file)
            modules['StateManager'] = getattr(state_module, 'StateManager', None) if state_module else None
        else:
            modules['StateManager'] = None
            
        # VFS
        vfs_file = _find_gpt_pilot_file("core.disk.vfs")
        if vfs_file:
            vfs_module = _load_module_from_path("gpt_pilot_vfs", vfs_file)
            modules['VFS'] = getattr(vfs_module, 'VFS', None) if vfs_module else None
        else:
            modules['VFS'] = None
        
        # Проверяем, что хотя бы основные модули загружены
        available = any(modules[key] is not None for key in ['Project', 'Branch', 'UserSettings'])
        
        modules['available'] = available
        if not available:
            modules['error'] = "No GPT-Pilot modules could be loaded"
            
        logger.info(f"GPT-Pilot modules loaded: {available}")
        return modules
        
    except Exception as e:
        logger.warning(f"Failed to load GPT-Pilot modules: {e}")
        return _create_fallback_modules(str(e))

def _create_fallback_modules(error_msg: str) -> Dict[str, Any]:
    """Создает fallback модули при ошибке загрузки"""
    return {
        'Project': None,
        'Branch': None,
        'UserSettings': None,
        'Orchestrator': None,
        'get_session': None,
        'StateManager': None,
        'VFS': None,
        'available': False,
        'error': error_msg
    }

# Глобальный кэш импортов
_gpt_pilot_modules: Optional[Dict[str, Any]] = None

def get_gpt_pilot_modules() -> Dict[str, Any]:
    """Получить GPT-Pilot модули (с кэшированием)"""
    global _gpt_pilot_modules
    if _gpt_pilot_modules is None:
        _gpt_pilot_modules = safe_import_gpt_pilot()
    return _gpt_pilot_modules

def is_gpt_pilot_available() -> bool:
    """Проверить доступность GPT-Pilot"""
    modules = get_gpt_pilot_modules()
    return modules.get('available', False)

def clear_gpt_pilot_cache():
    """Очистить кэш GPT-Pilot модулей (для тестов)"""
    global _gpt_pilot_modules
    _gpt_pilot_modules = None