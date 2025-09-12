#!/usr/bin/env python3
"""
Тесты для SamokoderGPTPilotSimpleAdapter
"""

import pytest
import asyncio
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from backend.services.gpt_pilot_simple_adapter import SamokoderGPTPilotSimpleAdapter


class TestSamokoderGPTPilotSimpleAdapter:
    """Тесты для SamokoderGPTPilotSimpleAdapter"""
    
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
        
        with patch('backend.services.gpt_pilot_simple_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            self.adapter = SamokoderGPTPilotSimpleAdapter(
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
    
    @patch('backend.services.gpt_pilot_simple_adapter.os.environ')
    def test_setup_api_config_openrouter(self, mock_environ):
        """Тест настройки API конфигурации с OpenRouter"""
        # Создаем новый адаптер для тестирования setup_api_config
        with patch('backend.services.gpt_pilot_simple_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            adapter = SamokoderGPTPilotSimpleAdapter(
                self.project_id, 
                self.user_id, 
                {"openrouter": "test_key"}
            )
        
        # Проверяем что переменные окружения установлены
        assert mock_environ['OPENROUTER_API_KEY'] == "test_key"
        assert mock_environ['MODEL_NAME'] == 'deepseek/deepseek-v3'
        assert mock_environ['ENDPOINT'] == 'OPENROUTER'
    
    @patch('backend.services.gpt_pilot_simple_adapter.os.environ')
    def test_setup_api_config_openai(self, mock_environ):
        """Тест настройки API конфигурации с OpenAI"""
        # Создаем новый адаптер для тестирования setup_api_config
        with patch('backend.services.gpt_pilot_simple_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            adapter = SamokoderGPTPilotSimpleAdapter(
                self.project_id, 
                self.user_id, 
                {"openai": "test_key"}
            )
        
        # Проверяем что переменные окружения установлены
        assert mock_environ['OPENAI_API_KEY'] == "test_key"
        assert mock_environ['MODEL_NAME'] == 'gpt-4o-mini'
        assert mock_environ['ENDPOINT'] == 'OPENAI'
    
    @patch('backend.services.gpt_pilot_simple_adapter.os.environ')
    def test_setup_api_config_fallback(self, mock_environ):
        """Тест настройки API конфигурации с fallback"""
        # Создаем новый адаптер для тестирования setup_api_config
        with patch('backend.services.gpt_pilot_simple_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            adapter = SamokoderGPTPilotSimpleAdapter(
                self.project_id, 
                self.user_id, 
                {}
            )
        
        # Проверяем что используется fallback
        assert mock_environ['MODEL_NAME'] == 'deepseek/deepseek-v3'
        assert mock_environ['ENDPOINT'] == 'OPENROUTER'
    
    def test_get_project_info_not_initialized(self):
        """Тест получения информации о проекте когда не инициализирован"""
        info = self.adapter.get_project_info()
        
        assert info == {
            "project_id": self.project_id,
            "user_id": self.user_id,
            "initialized": False,
            "workspace": str(self.adapter.workspace),
            "status": "not_initialized"
        }
    
    def test_get_project_info_initialized(self):
        """Тест получения информации о проекте когда инициализирован"""
        # Инициализируем проект
        self.adapter.initialized = True
        self.adapter.project_data = {"name": "Test Project", "description": "Test Description"}
        
        info = self.adapter.get_project_info()
        
        assert info["initialized"] == True
        assert info["project_data"] == {"name": "Test Project", "description": "Test Description"}
    
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
    
    def test_validate_requirements_missing_architecture(self):
        """Тест валидации требований - отсутствует архитектура"""
        requirements = {
            "description": "Test project",
            "features": ["auth"]
        }
        
        result = self.adapter.validate_requirements(requirements)
        
        assert result["valid"] == False
        assert "architecture" in str(result["errors"])
    
    def test_validate_requirements_empty_features(self):
        """Тест валидации требований - пустые функции"""
        requirements = {
            "description": "Test project",
            "architecture": "FastAPI",
            "features": []
        }
        
        result = self.adapter.validate_requirements(requirements)
        
        assert result["valid"] == False
        assert "features" in str(result["errors"])
    
    def test_generate_project_structure(self):
        """Тест генерации структуры проекта"""
        requirements = {
            "description": "Test project",
            "architecture": "FastAPI",
            "features": ["auth", "database"]
        }
        
        with patch.object(self.adapter, '_create_basic_structure') as mock_create:
            mock_create.return_value = {"files_created": 5}
            
            result = self.adapter.generate_project_structure(requirements)
        
        assert result["success"] == True
        assert result["files_created"] == 5
        mock_create.assert_called_once()
    
    def test_generate_project_structure_invalid_requirements(self):
        """Тест генерации структуры проекта с невалидными требованиями"""
        requirements = {
            "description": "Test project"
            # Отсутствует architecture
        }
        
        result = self.adapter.generate_project_structure(requirements)
        
        assert result["success"] == False
        assert "validation" in result["error"]
    
    def test_generate_code_basic(self):
        """Тест базовой генерации кода"""
        prompt = "Create a simple FastAPI app"
        
        with patch.object(self.adapter, '_generate_with_mock_ai') as mock_generate:
            mock_generate.return_value = {
                "code": "from fastapi import FastAPI\napp = FastAPI()",
                "files": ["main.py"]
            }
            
            result = self.adapter.generate_code(prompt)
        
        assert result["success"] == True
        assert "code" in result
        assert "files" in result
    
    def test_generate_code_with_context(self):
        """Тест генерации кода с контекстом"""
        prompt = "Add authentication"
        context = {"existing_files": ["main.py"], "current_structure": "FastAPI"}
        
        with patch.object(self.adapter, '_generate_with_mock_ai') as mock_generate:
            mock_generate.return_value = {
                "code": "from fastapi import FastAPI, Depends",
                "files": ["auth.py"]
            }
            
            result = self.adapter.generate_code(prompt, context)
        
        assert result["success"] == True
        mock_generate.assert_called_once()
    
    def test_generate_code_error(self):
        """Тест генерации кода с ошибкой"""
        prompt = ""
        
        result = self.adapter.generate_code(prompt)
        
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
        with patch('backend.services.gpt_pilot_simple_adapter.shutil.rmtree') as mock_rmtree:
            result = self.adapter.cleanup_workspace()
        
        assert result["success"] == True
        mock_rmtree.assert_called_once()
    
    def test_cleanup_workspace_error(self):
        """Тест очистки рабочей директории с ошибкой"""
        with patch('backend.services.gpt_pilot_simple_adapter.shutil.rmtree') as mock_rmtree:
            mock_rmtree.side_effect = Exception("Permission denied")
            
            result = self.adapter.cleanup_workspace()
        
        assert result["success"] == False
        assert "error" in result
    
    def test_get_workspace_info(self):
        """Тест получения информации о рабочей директории"""
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_workspace.exists.return_value = True
            mock_workspace.is_dir.return_value = True
            mock_workspace.stat.return_value.st_size = 1024
            
            info = self.adapter.get_workspace_info()
        
        assert info["exists"] == True
        assert info["is_directory"] == True
        assert info["path"] == str(mock_workspace)
    
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