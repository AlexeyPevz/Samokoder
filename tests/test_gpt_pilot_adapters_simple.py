#!/usr/bin/env python3
"""
Упрощенные тесты для GPT Pilot адаптеров
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from backend.services.gpt_pilot_simple_adapter import SamokoderGPTPilotSimpleAdapter
from backend.services.gpt_pilot_real_adapter import SamokoderGPTPilotRealAdapter


class TestSamokoderGPTPilotSimpleAdapter:
    """Упрощенные тесты для SamokoderGPTPilotSimpleAdapter"""
    
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
        assert mock_environ.__setitem__.call_count >= 3  # OPENROUTER_API_KEY, MODEL_NAME, ENDPOINT
    
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
        assert mock_environ.__setitem__.call_count >= 3  # OPENAI_API_KEY, MODEL_NAME, ENDPOINT
    
    @patch('backend.services.gpt_pilot_simple_adapter.os.environ')
    @patch('backend.services.gpt_pilot_simple_adapter.os.getenv')
    def test_setup_api_config_fallback(self, mock_getenv, mock_environ):
        """Тест настройки API конфигурации с fallback"""
        mock_getenv.return_value = None  # Нет системных ключей
        
        # Создаем новый адаптер для тестирования setup_api_config
        with patch('backend.services.gpt_pilot_simple_adapter.Path') as mock_path:
            mock_path.return_value.mkdir = Mock()
            adapter = SamokoderGPTPilotSimpleAdapter(
                self.project_id, 
                self.user_id, 
                {}
            )
        
        # Проверяем что переменные окружения установлены (dummy keys)
        assert mock_environ.__setitem__.call_count >= 3
    
    @pytest.mark.asyncio
    async def test_initialize_project_success(self):
        """Тест инициализации проекта - успех"""
        app_name = "Test App"
        app_description = "Test Description"
        
        with patch.object(self.adapter, '_create_basic_project_structure') as mock_create:
            mock_create.return_value = AsyncMock()
            
            result = await self.adapter.initialize_project(app_name, app_description)
        
        assert result["status"] == "initialized"
        assert result["project_id"] is not None
        assert self.adapter.initialized == True
        assert self.adapter.project_data is not None
        mock_create.assert_called_once_with(app_name, app_description)
    
    @pytest.mark.asyncio
    async def test_initialize_project_error(self):
        """Тест инициализации проекта с ошибкой"""
        app_name = "Test App"
        app_description = "Test Description"
        
        with patch.object(self.adapter, '_create_basic_project_structure') as mock_create:
            mock_create.side_effect = Exception("Test error")
            
            result = await self.adapter.initialize_project(app_name, app_description)
        
        assert result["status"] == "error"
        assert "error" in result
        assert self.adapter.initialized == False
    
    def test_get_project_files_not_initialized(self):
        """Тест получения файлов проекта когда не инициализирован"""
        files = self.adapter.get_project_files()
        
        assert files == []
    
    def test_get_project_files_initialized(self):
        """Тест получения файлов проекта когда инициализирован"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_file = Mock()
            mock_file.is_file.return_value = True
            mock_file.name = "test.py"
            mock_workspace.glob.return_value = [mock_file]
            
            files = self.adapter.get_project_files()
        
        assert len(files) == 1
        assert files[0]["name"] == "test.py"
    
    def test_get_project_files_error(self):
        """Тест получения файлов проекта с ошибкой"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_workspace.glob.side_effect = Exception("Permission denied")
            
            files = self.adapter.get_project_files()
        
        assert files == []
    
    def test_get_workspace_size_not_initialized(self):
        """Тест получения размера рабочей директории когда не инициализирован"""
        size = self.adapter.get_workspace_size()
        
        assert size == 0
    
    def test_get_workspace_size_initialized(self):
        """Тест получения размера рабочей директории когда инициализирован"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_workspace.exists.return_value = True
            mock_file = Mock()
            mock_file.stat.return_value.st_size = 1024
            mock_workspace.rglob.return_value = [mock_file]
            
            size = self.adapter.get_workspace_size()
        
        assert size == 1024
    
    def test_get_workspace_size_error(self):
        """Тест получения размера рабочей директории с ошибкой"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_workspace.exists.return_value = True
            mock_workspace.rglob.side_effect = Exception("Permission denied")
            
            size = self.adapter.get_workspace_size()
        
        assert size == 0


class TestSamokoderGPTPilotRealAdapter:
    """Упрощенные тесты для SamokoderGPTPilotRealAdapter"""
    
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
        assert str(self.adapter.gpt_pilot_path) == "samokoder-core"
    
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
        assert mock_environ.__setitem__.call_count >= 3
    
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
        assert mock_environ.__setitem__.call_count >= 3
    
    @pytest.mark.asyncio
    async def test_initialize_project_success(self):
        """Тест инициализации проекта - успех"""
        app_name = "Test App"
        app_description = "Test Description"
        
        with patch.object(self.adapter, '_create_basic_project_structure') as mock_create, \
             patch.object(self.adapter, '_initialize_gpt_pilot') as mock_init:
            mock_create.return_value = AsyncMock()
            mock_init.return_value = AsyncMock()
            
            result = await self.adapter.initialize_project(app_name, app_description)
        
        assert result["status"] == "initialized"
        assert result["project_id"] is not None
        assert self.adapter.initialized == True
        assert self.adapter.project_data is not None
        mock_create.assert_called_once_with(app_name, app_description)
        mock_init.assert_called_once_with(app_name, app_description)
    
    @pytest.mark.asyncio
    async def test_initialize_project_error(self):
        """Тест инициализации проекта с ошибкой"""
        app_name = "Test App"
        app_description = "Test Description"
        
        with patch.object(self.adapter, '_create_basic_project_structure') as mock_create:
            mock_create.side_effect = Exception("Test error")
            
            result = await self.adapter.initialize_project(app_name, app_description)
        
        assert result["status"] == "error"
        assert "error" in result
        assert self.adapter.initialized == False
    
    def test_get_project_files_not_initialized(self):
        """Тест получения файлов проекта когда не инициализирован"""
        files = self.adapter.get_project_files()
        
        assert files == []
    
    def test_get_project_files_initialized(self):
        """Тест получения файлов проекта когда инициализирован"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_file = Mock()
            mock_file.is_file.return_value = True
            mock_file.name = "test.py"
            mock_workspace.glob.return_value = [mock_file]
            
            files = self.adapter.get_project_files()
        
        assert len(files) == 1
        assert files[0]["name"] == "test.py"
    
    def test_get_project_files_error(self):
        """Тест получения файлов проекта с ошибкой"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_workspace.glob.side_effect = Exception("Permission denied")
            
            files = self.adapter.get_project_files()
        
        assert files == []
    
    def test_get_workspace_size_not_initialized(self):
        """Тест получения размера рабочей директории когда не инициализирован"""
        size = self.adapter.get_workspace_size()
        
        assert size == 0
    
    def test_get_workspace_size_initialized(self):
        """Тест получения размера рабочей директории когда инициализирован"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_workspace.exists.return_value = True
            mock_file = Mock()
            mock_file.stat.return_value.st_size = 1024
            mock_workspace.rglob.return_value = [mock_file]
            
            size = self.adapter.get_workspace_size()
        
        assert size == 1024
    
    def test_get_workspace_size_error(self):
        """Тест получения размера рабочей директории с ошибкой"""
        self.adapter.initialized = True
        
        with patch.object(self.adapter, 'workspace') as mock_workspace:
            mock_workspace.exists.return_value = True
            mock_workspace.rglob.side_effect = Exception("Permission denied")
            
            size = self.adapter.get_workspace_size()
        
        assert size == 0
    
    def test_get_project_status_not_initialized(self):
        """Тест получения статуса проекта когда не инициализирован"""
        status = self.adapter.get_project_status()
        
        assert status["status"] == "not_initialized"
        assert status["initialized"] == False
    
    def test_get_project_status_initialized(self):
        """Тест получения статуса проекта когда инициализирован"""
        self.adapter.initialized = True
        self.adapter.project_data = {"name": "Test Project", "status": "active"}
        
        status = self.adapter.get_project_status()
        
        assert status["status"] == "initialized"
        assert status["initialized"] == True
        assert status["project_data"] == {"name": "Test Project", "status": "active"}
    
    def test_get_project_info_not_initialized(self):
        """Тест получения информации о проекте когда не инициализирован"""
        info = self.adapter.get_project_info()
        
        assert info["project_id"] == self.project_id
        assert info["user_id"] == self.user_id
        assert info["initialized"] == False
        assert info["status"] == "not_initialized"
    
    def test_get_project_info_initialized(self):
        """Тест получения информации о проекте когда инициализирован"""
        self.adapter.initialized = True
        self.adapter.project_data = {"name": "Test Project"}
        
        info = self.adapter.get_project_info()
        
        assert info["initialized"] == True
        assert info["project_data"] == {"name": "Test Project"}