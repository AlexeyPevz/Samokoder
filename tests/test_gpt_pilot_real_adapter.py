#!/usr/bin/env python3
"""
Тесты для SamokoderGPTPilotRealAdapter
"""

import pytest
import asyncio
import json
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from backend.services.gpt_pilot_real_adapter import SamokoderGPTPilotRealAdapter


class TestSamokoderGPTPilotRealAdapter:
    """Тесты для SamokoderGPTPilotRealAdapter"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.project_id = "test_project_123"
        self.user_id = "test_user_456"
        self.user_api_keys = {
            "openrouter": "test_openrouter_key",
            "openai": "test_openai_key"
        }
        
        # Создаем временную директорию
        self.temp_dir = tempfile.mkdtemp()
        
        with patch('backend.services.gpt_pilot_real_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            self.adapter = SamokoderGPTPilotRealAdapter(
                self.project_id, 
                self.user_id, 
                self.user_api_keys
            )
    
    def teardown_method(self):
        """Очистка после каждого теста"""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Тест инициализации адаптера"""
        assert self.adapter.project_id == self.project_id
        assert self.adapter.user_id == self.user_id
        assert self.adapter.user_api_keys == self.user_api_keys
        assert self.adapter.initialized == False
        assert self.adapter.project_data is None
        assert self.adapter.gpt_pilot_path == Path("samokoder-core")
    
    @patch('backend.services.gpt_pilot_real_adapter.os.environ')
    def test_setup_api_config_openrouter(self, mock_environ):
        """Тест настройки API конфигурации с OpenRouter"""
        # Создаем новый адаптер для тестирования setup_api_config
        with patch('backend.services.gpt_pilot_real_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            adapter = SamokoderGPTPilotRealAdapter(
                self.project_id, 
                self.user_id, 
                {"openrouter": "test_key"}
            )
        
        # Проверяем что переменные окружения установлены
        assert mock_environ['OPENROUTER_API_KEY'] == "test_key"
        assert mock_environ['MODEL_NAME'] == 'deepseek/deepseek-v3'
        assert mock_environ['ENDPOINT'] == 'OPENROUTER'
    
    @patch('backend.services.gpt_pilot_real_adapter.os.environ')
    def test_setup_api_config_openai(self, mock_environ):
        """Тест настройки API конфигурации с OpenAI"""
        # Создаем новый адаптер для тестирования setup_api_config
        with patch('backend.services.gpt_pilot_real_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            adapter = SamokoderGPTPilotRealAdapter(
                self.project_id, 
                self.user_id, 
                {"openai": "test_key"}
            )
        
        # Проверяем что переменные окружения установлены
        assert mock_environ['OPENAI_API_KEY'] == "test_key"
        assert mock_environ['MODEL_NAME'] == 'gpt-4o-mini'
        assert mock_environ['ENDPOINT'] == 'OPENAI'
    
    def test_check_gpt_pilot_installation_not_found(self):
        """Тест проверки установки GPT-Pilot - не найден"""
        with patch.object(self.adapter, 'gpt_pilot_path') as mock_path:
            mock_path.exists.return_value = False
            
            result = self.adapter.check_gpt_pilot_installation()
        
        assert result["installed"] == False
        assert "not found" in result["error"]
    
    def test_check_gpt_pilot_installation_found(self):
        """Тест проверки установки GPT-Pilot - найден"""
        with patch.object(self.adapter, 'gpt_pilot_path') as mock_path:
            mock_path.exists.return_value = True
            mock_path.is_dir.return_value = True
            
            result = self.adapter.check_gpt_pilot_installation()
        
        assert result["installed"] == True
        assert result["path"] == str(mock_path)
    
    def test_install_gpt_pilot_success(self):
        """Тест установки GPT-Pilot - успех"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            
            result = self.adapter.install_gpt_pilot()
        
        assert result["success"] == True
        assert "installed" in result["message"]
    
    def test_install_gpt_pilot_failure(self):
        """Тест установки GPT-Pilot - неудача"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "Permission denied"
            
            result = self.adapter.install_gpt_pilot()
        
        assert result["success"] == False
        assert "error" in result
    
    def test_validate_requirements_success(self):
        """Тест валидации требований - успех"""
        requirements = {
            "description": "Test project",
            "architecture": "FastAPI",
            "features": ["auth", "database"]
        }
        
        result = self.adapter.validate_requirements(requirements)
        
        assert result["valid"] == True
        assert result["errors"] == []
    
    def test_validate_requirements_missing_description(self):
        """Тест валидации требований - отсутствует описание"""
        requirements = {
            "architecture": "FastAPI",
            "features": ["auth"]
        }
        
        result = self.adapter.validate_requirements(requirements)
        
        assert result["valid"] == False
        assert "description" in str(result["errors"])
    
    def test_generate_project_structure_success(self):
        """Тест генерации структуры проекта - успех"""
        requirements = {
            "description": "Test project",
            "architecture": "FastAPI",
            "features": ["auth", "database"]
        }
        
        with patch.object(self.adapter, '_execute_gpt_pilot_command') as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "output": "Project structure generated",
                "files_created": 5
            }
            
            result = self.adapter.generate_project_structure(requirements)
        
        assert result["success"] == True
        assert result["files_created"] == 5
        mock_execute.assert_called_once()
    
    def test_generate_project_structure_failure(self):
        """Тест генерации структуры проекта - неудача"""
        requirements = {
            "description": "Test project",
            "architecture": "FastAPI",
            "features": ["auth", "database"]
        }
        
        with patch.object(self.adapter, '_execute_gpt_pilot_command') as mock_execute:
            mock_execute.return_value = {
                "success": False,
                "error": "Command failed"
            }
            
            result = self.adapter.generate_project_structure(requirements)
        
        assert result["success"] == False
        assert "error" in result
    
    def test_generate_code_success(self):
        """Тест генерации кода - успех"""
        prompt = "Create a simple FastAPI app"
        
        with patch.object(self.adapter, '_execute_gpt_pilot_command') as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "output": "Code generated successfully",
                "files": ["main.py", "auth.py"]
            }
            
            result = self.adapter.generate_code(prompt)
        
        assert result["success"] == True
        assert "files" in result
        mock_execute.assert_called_once()
    
    def test_generate_code_with_context(self):
        """Тест генерации кода с контекстом"""
        prompt = "Add authentication"
        context = {"existing_files": ["main.py"]}
        
        with patch.object(self.adapter, '_execute_gpt_pilot_command') as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "output": "Authentication added",
                "files": ["auth.py"]
            }
            
            result = self.adapter.generate_code(prompt, context)
        
        assert result["success"] == True
        mock_execute.assert_called_once()
    
    def test_generate_code_empty_prompt(self):
        """Тест генерации кода с пустым промптом"""
        result = self.adapter.generate_code("")
        
        assert result["success"] == False
        assert "empty" in result["error"].lower()
    
    def test_iterative_development_success(self):
        """Тест итеративной разработки - успех"""
        iterations = [
            {"prompt": "Create basic app", "context": {}},
            {"prompt": "Add database", "context": {"existing_files": ["main.py"]}}
        ]
        
        with patch.object(self.adapter, 'generate_code') as mock_generate:
            mock_generate.side_effect = [
                {"success": True, "code": "app1", "files": ["main.py"]},
                {"success": True, "code": "app2", "files": ["database.py"]}
            ]
            
            results = list(self.adapter.iterative_development(iterations))
        
        assert len(results) == 2
        assert all(r["success"] for r in results)
        assert mock_generate.call_count == 2
    
    def test_iterative_development_with_error(self):
        """Тест итеративной разработки с ошибкой"""
        iterations = [
            {"prompt": "Create basic app", "context": {}},
            {"prompt": "", "context": {}}  # Пустой промпт вызовет ошибку
        ]
        
        with patch.object(self.adapter, 'generate_code') as mock_generate:
            mock_generate.side_effect = [
                {"success": True, "code": "app1", "files": ["main.py"]},
                {"success": False, "error": "Empty prompt"}
            ]
            
            results = list(self.adapter.iterative_development(iterations))
        
        assert len(results) == 2
        assert results[0]["success"] == True
        assert results[1]["success"] == False
    
    def test_execute_gpt_pilot_command_success(self):
        """Тест выполнения команды GPT-Pilot - успех"""
        command = ["python", "gpt_pilot.py", "generate"]
        
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Success output"
            mock_run.return_value.stderr = ""
            
            result = self.adapter._execute_gpt_pilot_command(command)
        
        assert result["success"] == True
        assert result["output"] == "Success output"
        assert result["error"] == ""
    
    def test_execute_gpt_pilot_command_failure(self):
        """Тест выполнения команды GPT-Pilot - неудача"""
        command = ["python", "gpt_pilot.py", "generate"]
        
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = "Command failed"
            
            result = self.adapter._execute_gpt_pilot_command(command)
        
        assert result["success"] == False
        assert result["output"] == ""
        assert result["error"] == "Command failed"
    
    def test_execute_gpt_pilot_command_exception(self):
        """Тест выполнения команды GPT-Pilot с исключением"""
        command = ["python", "gpt_pilot.py", "generate"]
        
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("Command not found")
            
            result = self.adapter._execute_gpt_pilot_command(command)
        
        assert result["success"] == False
        assert "error" in result
    
    def test_get_project_info_not_initialized(self):
        """Тест получения информации о проекте когда не инициализирован"""
        info = self.adapter.get_project_info()
        
        assert info == {
            "project_id": self.project_id,
            "user_id": self.user_id,
            "initialized": False,
            "workspace": str(self.adapter.workspace),
            "gpt_pilot_path": str(self.adapter.gpt_pilot_path),
            "status": "not_initialized"
        }
    
    def test_get_project_info_initialized(self):
        """Тест получения информации о проекте когда инициализирован"""
        # Инициализируем проект
        self.adapter.initialized = True
        self.adapter.project_data = {"name": "Test Project", "files": 5}
        
        info = self.adapter.get_project_info()
        
        assert info["initialized"] == True
        assert info["project_data"] == {"name": "Test Project", "files": 5}
    
    def test_get_generation_status_not_initialized(self):
        """Тест получения статуса генерации когда не инициализирован"""
        status = self.adapter.get_generation_status()
        
        assert status["status"] == "not_initialized"
        assert status["progress"] == 0
    
    def test_get_generation_status_initialized(self):
        """Тест получения статуса генерации когда инициализирован"""
        self.adapter.initialized = True
        self.adapter.project_data = {"files_generated": 3, "total_files": 5}
        
        status = self.adapter.get_generation_status()
        
        assert status["status"] == "initialized"
        assert status["progress"] == 60  # 3/5 * 100
    
    def test_cleanup_workspace(self):
        """Тест очистки рабочей директории"""
        with patch('backend.services.gpt_pilot_real_adapter.shutil.rmtree') as mock_rmtree:
            result = self.adapter.cleanup_workspace()
        
        assert result["success"] == True
        mock_rmtree.assert_called_once()
    
    def test_cleanup_workspace_error(self):
        """Тест очистки рабочей директории с ошибкой"""
        with patch('backend.services.gpt_pilot_real_adapter.shutil.rmtree') as mock_rmtree:
            mock_rmtree.side_effect = Exception("Permission denied")
            
            result = self.adapter.cleanup_workspace()
        
        assert result["success"] == False
        assert "error" in result
    
    def test_validate_api_keys_success(self):
        """Тест валидации API ключей - успех"""
        with patch.object(self.adapter, '_test_api_connection') as mock_test:
            mock_test.return_value = True
            
            result = self.adapter.validate_api_keys()
        
        assert result["valid"] == True
        assert result["errors"] == []
    
    def test_validate_api_keys_failure(self):
        """Тест валидации API ключей - неудача"""
        with patch.object(self.adapter, '_test_api_connection') as mock_test:
            mock_test.return_value = False
            
            result = self.adapter.validate_api_keys()
        
        assert result["valid"] == False
        assert len(result["errors"]) > 0
    
    def test_get_supported_features(self):
        """Тест получения поддерживаемых функций"""
        features = self.adapter.get_supported_features()
        
        assert isinstance(features, list)
        assert len(features) > 0
        assert "auth" in features
        assert "database" in features
    
    def test_get_supported_architectures(self):
        """Тест получения поддерживаемых архитектур"""
        architectures = self.adapter.get_supported_architectures()
        
        assert isinstance(architectures, list)
        assert len(architectures) > 0
        assert "FastAPI" in architectures
        assert "Django" in architectures
    
    def test_check_dependencies_success(self):
        """Тест проверки зависимостей - успех"""
        with patch.object(self.adapter, 'gpt_pilot_path') as mock_path:
            mock_path.exists.return_value = True
            mock_path.joinpath.return_value.exists.return_value = True
            
            result = self.adapter.check_dependencies()
        
        assert result["all_dependencies_met"] == True
        assert len(result["missing_dependencies"]) == 0
    
    def test_check_dependencies_missing(self):
        """Тест проверки зависимостей - отсутствуют"""
        with patch.object(self.adapter, 'gpt_pilot_path') as mock_path:
            mock_path.exists.return_value = True
            mock_path.joinpath.return_value.exists.return_value = False
            
            result = self.adapter.check_dependencies()
        
        assert result["all_dependencies_met"] == False
        assert len(result["missing_dependencies"]) > 0