#!/usr/bin/env python3
"""
Рабочие тесты для GPT Pilot Wrapper v2
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from pathlib import Path
from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot


class TestSamokoderGPTPilotWorking:
    """Рабочие тесты для SamokoderGPTPilot"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.project_id = "test_project"
        self.user_id = "test_user"
        self.user_api_keys = {
            "openai": "sk-test123",
            "anthropic": "ant-test123"
        }
    
    @patch('backend.services.gpt_pilot_wrapper_v2.SamokoderGPTPilotRealAdapter')
    @patch('backend.services.gpt_pilot_wrapper_v2.Path')
    def test_init_with_real_adapter_success(self, mock_path, mock_real_adapter):
        """Тест инициализации с реальным адаптером"""
        mock_adapter = Mock()
        mock_real_adapter.return_value = mock_adapter
        mock_path_instance = Mock()
        mock_path.return_value = mock_path_instance
        
        pilot = SamokoderGPTPilot(self.project_id, self.user_id, self.user_api_keys)
        
        assert pilot.project_id == self.project_id
        assert pilot.user_id == self.user_id
        assert pilot.user_api_keys == self.user_api_keys
        assert pilot.adapter == mock_adapter
        mock_real_adapter.assert_called_once_with(self.project_id, self.user_id, self.user_api_keys)
        mock_path_instance.mkdir.assert_called_once_with(parents=True, exist_ok=True)
    
    @patch('backend.services.gpt_pilot_wrapper_v2.SamokoderGPTPilotRealAdapter')
    @patch('backend.services.gpt_pilot_wrapper_v2.SamokoderGPTPilotSimpleAdapter')
    @patch('backend.services.gpt_pilot_wrapper_v2.Path')
    def test_init_with_fallback_to_simple_adapter(self, mock_path, mock_simple_adapter, mock_real_adapter):
        """Тест инициализации с fallback на простой адаптер"""
        # Реальный адаптер выбрасывает исключение
        mock_real_adapter.side_effect = Exception("Real adapter failed")
        mock_simple_adapter_instance = Mock()
        mock_simple_adapter.return_value = mock_simple_adapter_instance
        mock_path_instance = Mock()
        mock_path.return_value = mock_path_instance
        
        pilot = SamokoderGPTPilot(self.project_id, self.user_id, self.user_api_keys)
        
        assert pilot.adapter == mock_simple_adapter_instance
        mock_real_adapter.assert_called_once()
        mock_simple_adapter.assert_called_once_with(self.project_id, self.user_id, self.user_api_keys)
    
    @pytest.mark.asyncio
    async def test_initialize_project_success(self):
        """Тест успешной инициализации проекта"""
        mock_adapter = Mock()
        mock_adapter.initialize_project = AsyncMock(return_value={
            'project_id': self.project_id,
            'status': 'success',
            'message': 'Project initialized'
        })
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.adapter = mock_adapter
        
        app_description = "Test application"
        app_name = "Test App"
        
        result = await pilot.initialize_project(app_description, app_name)
        
        assert result['project_id'] == self.project_id
        assert result['status'] == 'success'
        mock_adapter.initialize_project.assert_called_once_with(app_name, app_description)
    
    @pytest.mark.asyncio
    async def test_initialize_project_error(self):
        """Тест инициализации проекта с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.initialize_project = AsyncMock(side_effect=Exception("Initialization failed"))
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.adapter = mock_adapter
        
        result = await pilot.initialize_project("Test description")
        
        assert result['project_id'] == self.project_id
        assert result['status'] == 'error'
        assert 'error' in result
        assert 'Ошибка инициализации проекта' in result['message']
    
    @pytest.mark.asyncio
    async def test_chat_with_agents_success(self):
        """Тест успешного чата с агентами"""
        mock_adapter = Mock()
        mock_updates = [
            {'type': 'message', 'content': 'Hello'},
            {'type': 'response', 'content': 'Hi there!'}
        ]
        
        async def mock_chat_generator(message, context):
            for update in mock_updates:
                yield update
        
        mock_adapter.chat_with_agents = mock_chat_generator
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.adapter = mock_adapter
        
        message = "Hello"
        context = "chat"
        
        result_updates = []
        async for update in pilot.chat_with_agents(message, context):
            result_updates.append(update)
        
        assert len(result_updates) == 2
        assert result_updates[0]['type'] == 'message'
        assert result_updates[1]['type'] == 'response'
    
    @pytest.mark.asyncio
    async def test_chat_with_agents_error(self):
        """Тест чата с агентами с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.chat_with_agents = AsyncMock(side_effect=Exception("Chat error"))
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.adapter = mock_adapter
        
        result_updates = []
        async for update in pilot.chat_with_agents("Hello"):
            result_updates.append(update)
        
        assert len(result_updates) == 1
        assert result_updates[0]['type'] == 'error'
        assert 'Ошибка в работе агентов' in result_updates[0]['message']
    
    @pytest.mark.asyncio
    async def test_generate_full_app_success(self):
        """Тест успешной генерации полного приложения"""
        mock_adapter = Mock()
        mock_updates = [
            {'type': 'progress', 'step': 1},
            {'type': 'progress', 'step': 2},
            {'type': 'complete', 'status': 'success'}
        ]
        
        async def mock_generate_generator():
            for update in mock_updates:
                yield update
        
        mock_adapter.generate_full_app = mock_generate_generator
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.adapter = mock_adapter
        
        result_updates = []
        async for update in pilot.generate_full_app():
            result_updates.append(update)
        
        assert len(result_updates) == 3
        assert result_updates[-1]['type'] == 'complete'
    
    @pytest.mark.asyncio
    async def test_generate_full_app_error(self):
        """Тест генерации полного приложения с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.generate_full_app = AsyncMock(side_effect=Exception("Generation error"))
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.adapter = mock_adapter
        
        result_updates = []
        async for update in pilot.generate_full_app():
            result_updates.append(update)
        
        assert len(result_updates) == 1
        assert result_updates[0]['type'] == 'error'
        assert 'Ошибка генерации' in result_updates[0]['message']
    
    def test_get_project_files_success(self):
        """Тест успешного получения файлов проекта"""
        mock_adapter = Mock()
        expected_files = {
            'main.py': {'size': 1024, 'type': 'file'},
            'config.json': {'size': 512, 'type': 'file'}
        }
        mock_adapter.get_project_files.return_value = expected_files
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = pilot.get_project_files()
        
        assert result == expected_files
        mock_adapter.get_project_files.assert_called_once()
    
    def test_get_project_files_error(self):
        """Тест получения файлов проекта с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.get_project_files.side_effect = Exception("Files error")
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = pilot.get_project_files()
        
        assert result == {}
    
    def test_get_file_content_success(self):
        """Тест успешного получения содержимого файла"""
        mock_adapter = Mock()
        expected_content = "print('Hello, World!')"
        mock_adapter.get_file_content.return_value = expected_content
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        file_path = "main.py"
        result = pilot.get_file_content(file_path)
        
        assert result == expected_content
        mock_adapter.get_file_content.assert_called_once_with(file_path)
    
    def test_get_file_content_error(self):
        """Тест получения содержимого файла с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.get_file_content.side_effect = Exception("File read error")
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        with pytest.raises(Exception, match="File read error"):
            pilot.get_file_content("nonexistent.py")
    
    def test_create_zip_export_success(self):
        """Тест успешного создания ZIP архива"""
        mock_adapter = Mock()
        expected_path = Path("/tmp/export.zip")
        mock_adapter.create_zip_export.return_value = expected_path
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = pilot.create_zip_export()
        
        assert result == expected_path
        mock_adapter.create_zip_export.assert_called_once()
    
    def test_create_zip_export_error(self):
        """Тест создания ZIP архива с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.create_zip_export.side_effect = Exception("Zip creation error")
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        with pytest.raises(Exception, match="Zip creation error"):
            pilot.create_zip_export()
    
    @pytest.mark.asyncio
    async def test_restore_from_workspace_success(self):
        """Тест успешного восстановления из workspace"""
        mock_adapter = Mock()
        mock_adapter.restore_from_workspace = AsyncMock()
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        pilot.initialize_project = AsyncMock()
        
        await pilot.restore_from_workspace()
        
        mock_adapter.restore_from_workspace.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_restore_from_workspace_error(self):
        """Тест восстановления из workspace с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.restore_from_workspace = AsyncMock(side_effect=Exception("Restore error"))
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        pilot.initialize_project = AsyncMock()
        
        await pilot.restore_from_workspace()
        
        mock_adapter.restore_from_workspace.assert_called_once()
        pilot.initialize_project.assert_called_once_with("Restored Project", "Восстановленный проект")
    
    def test_get_project_status_success(self):
        """Тест успешного получения статуса проекта"""
        mock_adapter = Mock()
        expected_status = {
            'project_id': self.project_id,
            'status': 'active',
            'initialized': True
        }
        mock_adapter.get_project_status.return_value = expected_status
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.user_id = self.user_id
        pilot.adapter = mock_adapter
        pilot.workspace = Path("/test/workspace")
        
        result = pilot.get_project_status()
        
        assert result == expected_status
        mock_adapter.get_project_status.assert_called_once()
    
    def test_get_project_status_error(self):
        """Тест получения статуса проекта с ошибкой"""
        mock_adapter = Mock()
        mock_adapter.get_project_status.side_effect = Exception("Status error")
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        pilot.user_id = self.user_id
        pilot.adapter = mock_adapter
        pilot.workspace = Path("/test/workspace")
        
        result = pilot.get_project_status()
        
        assert result['project_id'] == self.project_id
        assert result['user_id'] == self.user_id
        assert result['status'] == 'error'
        assert 'error' in result
    
    def test_get_workspace_path(self):
        """Тест получения пути к workspace"""
        expected_path = Path("/test/workspace")
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.workspace = expected_path
        
        result = pilot.get_workspace_path()
        
        assert result == expected_path
    
    def test_is_initialized_true(self):
        """Тест проверки инициализации - True"""
        mock_adapter = Mock()
        mock_adapter.initialized = True
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = pilot.is_initialized()
        
        assert result is True
    
    def test_is_initialized_false(self):
        """Тест проверки инициализации - False"""
        mock_adapter = Mock()
        mock_adapter.initialized = False
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = pilot.is_initialized()
        
        assert result is False
    
    @patch('backend.services.gpt_pilot_wrapper_v2.os.getenv')
    def test_get_api_config(self, mock_getenv):
        """Тест получения конфигурации API"""
        mock_getenv.side_effect = lambda key, default=None: {
            'ENDPOINT': 'OPENAI',
            'MODEL_NAME': 'gpt-4o-mini'
        }.get(key, default)
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.user_api_keys = {
            'openai': 'sk-test123',
            'anthropic': 'ant-test123',
            'groq': 'gq-test123',
            'openrouter': 'or-test123'
        }
        
        result = pilot.get_api_config()
        
        assert result['endpoint'] == 'OPENAI'
        assert result['model'] == 'gpt-4o-mini'
        assert result['has_openai'] is True
        assert result['has_anthropic'] is True
        assert result['has_groq'] is True
        assert result['has_openrouter'] is True
    
    @pytest.mark.asyncio
    async def test_update_project_description_success(self):
        """Тест успешного обновления описания проекта"""
        mock_adapter = Mock()
        mock_project = Mock()
        mock_adapter.project = mock_project
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        description = "Updated description"
        result = await pilot.update_project_description(description)
        
        assert result is True
        assert mock_project.name == description
    
    @pytest.mark.asyncio
    async def test_update_project_description_no_project(self):
        """Тест обновления описания проекта без проекта"""
        mock_adapter = Mock()
        mock_adapter.project = None
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = await pilot.update_project_description("New description")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_agent_status_initialized(self):
        """Тест получения статуса агентов - инициализирован"""
        mock_adapter = Mock()
        mock_adapter.initialized = True
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = await pilot.get_agent_status()
        
        assert result['status'] == 'active'
        assert result['current_agent'] == 'SamokoderGPT'
        assert result['progress'] == 100
        assert 'last_activity' in result
    
    @pytest.mark.asyncio
    async def test_get_agent_status_not_initialized(self):
        """Тест получения статуса агентов - не инициализирован"""
        mock_adapter = Mock()
        mock_adapter.initialized = False
        
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.adapter = mock_adapter
        
        result = await pilot.get_agent_status()
        
        assert result['status'] == 'not_initialized'
    
    def test_cleanup(self):
        """Тест очистки ресурсов"""
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.project_id = self.project_id
        
        # Должен выполниться без ошибок
        pilot.cleanup()
    
    def test_del(self):
        """Тест деструктора"""
        pilot = SamokoderGPTPilot.__new__(SamokoderGPTPilot)
        pilot.cleanup = Mock()
        
        pilot.__del__()
        
        pilot.cleanup.assert_called_once()