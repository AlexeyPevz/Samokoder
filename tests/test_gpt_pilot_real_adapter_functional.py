#!/usr/bin/env python3
"""
Функциональные тесты для GPT Pilot Real Adapter
Реальные тесты, которые выполняют код и увеличивают покрытие
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
import json
import tempfile
import os

from backend.services.gpt_pilot_real_adapter import SamokoderGPTPilotRealAdapter


class TestSamokoderGPTPilotRealAdapter:
    """Тесты для SamokoderGPTPilotRealAdapter"""
    
    @pytest.fixture
    def mock_api_keys(self):
        """Мок API ключей"""
        return {
            "openai": "sk-test123456789",
            "anthropic": "sk-ant-test123456789",
            "openrouter": "sk-or-test123456789"
        }
    
    def test_adapter_creation(self, mock_api_keys):
        """Тест создания адаптера"""
        adapter = SamokoderGPTPilotRealAdapter(
            project_id="test-project-123",
            user_id="test-user-456",
            user_api_keys=mock_api_keys
        )
        
        assert adapter.project_id == "test-project-123"
        assert adapter.user_id == "test-user-456"
        assert adapter.user_api_keys == mock_api_keys
        assert hasattr(adapter, 'workspace_path')
        assert hasattr(adapter, 'gpt_pilot_process')
    
    def test_adapter_creation_with_empty_api_keys(self):
        """Тест создания адаптера с пустыми API ключами"""
        adapter = SamokoderGPTPilotRealAdapter(
            project_id="test-project-123",
            user_id="test-user-456",
            user_api_keys={}
        )
        
        assert adapter.project_id == "test-project-123"
        assert adapter.user_id == "test-user-456"
        assert adapter.user_api_keys == {}
    
    @pytest.mark.asyncio
    async def test_initialize_project_success(self, mock_api_keys):
        """Тест успешной инициализации проекта"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None  # Процесс запущен
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.initialize_project()
            
            assert result is True
            mock_popen.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initialize_project_failure(self, mock_api_keys):
        """Тест неуспешной инициализации проекта"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_popen.side_effect = Exception("Failed to start process")
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.initialize_project()
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_generate_code_success(self, mock_api_keys):
        """Тест успешной генерации кода"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "code": "print(\\"Hello\\")"}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.generate_code("Create a hello world function")
            
            assert result is not None
            assert "status" in result
            assert "code" in result
    
    @pytest.mark.asyncio
    async def test_generate_code_failure(self, mock_api_keys):
        """Тест неуспешной генерации кода"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = 1  # Процесс завершился с ошибкой
            mock_process.stderr.readline.return_value = b'Error: API key invalid'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.generate_code("Create a hello world function")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_refactor_code_success(self, mock_api_keys):
        """Тест успешного рефакторинга кода"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "refactored_code": "def hello():\\n    print(\\"Hello World\\")"}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            original_code = "print('Hello')"
            refactored = await adapter.refactor_code(original_code, "Make it a function")
            
            assert refactored is not None
            assert "status" in refactored
            assert "refactored_code" in refactored
    
    @pytest.mark.asyncio
    async def test_debug_code_success(self, mock_api_keys):
        """Тест успешной отладки кода"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "debugged_code": "def hello():\\n    print(\\"Hello World\\")", "issues_found": ["Syntax error"]}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            buggy_code = "def hello()\\n    print('Hello')"
            result = await adapter.debug_code(buggy_code)
            
            assert result is not None
            assert "status" in result
            assert "debugged_code" in result
            assert "issues_found" in result
    
    @pytest.mark.asyncio
    async def test_explain_code_success(self, mock_api_keys):
        """Тест успешного объяснения кода"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "explanation": "This function prints hello world"}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            code = "def hello():\\n    print('Hello World')"
            result = await adapter.explain_code(code)
            
            assert result is not None
            assert "status" in result
            assert "explanation" in result
    
    @pytest.mark.asyncio
    async def test_get_project_status(self, mock_api_keys):
        """Тест получения статуса проекта"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "active", "files_count": 5, "last_modified": "2024-01-01T12:00:00Z"}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            status = await adapter.get_project_status()
            
            assert status is not None
            assert "status" in status
            assert "files_count" in status
            assert "last_modified" in status
    
    @pytest.mark.asyncio
    async def test_list_project_files(self, mock_api_keys):
        """Тест получения списка файлов проекта"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"files": ["main.py", "utils.py", "config.py"]}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            files = await adapter.list_project_files()
            
            assert files is not None
            assert "files" in files
            assert len(files["files"]) == 3
    
    @pytest.mark.asyncio
    async def test_get_file_content(self, mock_api_keys):
        """Тест получения содержимого файла"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"content": "def hello():\\n    print(\\"Hello World\\")", "size": 45}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            content = await adapter.get_file_content("main.py")
            
            assert content is not None
            assert "content" in content
            assert "size" in content
    
    @pytest.mark.asyncio
    async def test_save_file(self, mock_api_keys):
        """Тест сохранения файла"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "file_path": "main.py"}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            file_content = "def hello():\\n    print('Hello World')"
            result = await adapter.save_file("main.py", file_content)
            
            assert result is not None
            assert "status" in result
            assert "file_path" in result
    
    @pytest.mark.asyncio
    async def test_delete_file(self, mock_api_keys):
        """Тест удаления файла"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "deleted_file": "old_file.py"}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.delete_file("old_file.py")
            
            assert result is not None
            assert "status" in result
            assert "deleted_file" in result
    
    @pytest.mark.asyncio
    async def test_run_tests(self, mock_api_keys):
        """Тест запуска тестов"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "test_results": {"passed": 5, "failed": 0, "total": 5}}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            results = await adapter.run_tests()
            
            assert results is not None
            assert "status" in results
            assert "test_results" in results
            assert results["test_results"]["passed"] == 5
    
    @pytest.mark.asyncio
    async def test_get_usage_stats(self, mock_api_keys):
        """Тест получения статистики использования"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"tokens_used": 1000, "cost_usd": 0.01, "requests_count": 5}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            stats = await adapter.get_usage_stats()
            
            assert stats is not None
            assert "tokens_used" in stats
            assert "cost_usd" in stats
            assert "requests_count" in stats
    
    @pytest.mark.asyncio
    async def test_cleanup_project(self, mock_api_keys):
        """Тест очистки проекта"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "cleaned_files": 10}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.cleanup_project()
            
            assert result is not None
            assert "status" in result
            assert "cleaned_files" in result
    
    def test_validate_api_keys(self, mock_api_keys):
        """Тест валидации API ключей"""
        adapter = SamokoderGPTPilotRealAdapter(
            project_id="test-project-123",
            user_id="test-user-456",
            user_api_keys=mock_api_keys
        )
        
        # Тестируем валидные ключи
        assert adapter.validate_api_keys() is True
        
        # Тестируем с пустыми ключами
        adapter_empty = SamokoderGPTPilotRealAdapter(
            project_id="test-project-123",
            user_id="test-user-456",
            user_api_keys={}
        )
        
        assert adapter_empty.validate_api_keys() is False
    
    def test_get_workspace_path(self, mock_api_keys):
        """Тест получения пути к рабочей директории"""
        adapter = SamokoderGPTPilotRealAdapter(
            project_id="test-project-123",
            user_id="test-user-456",
            user_api_keys=mock_api_keys
        )
        
        workspace_path = adapter.get_workspace_path()
        
        assert workspace_path is not None
        assert isinstance(workspace_path, str)
        assert adapter.project_id in workspace_path
    
    def test_is_process_running(self, mock_api_keys):
        """Тест проверки запущенности процесса"""
        adapter = SamokoderGPTPilotRealAdapter(
            project_id="test-project-123",
            user_id="test-user-456",
            user_api_keys=mock_api_keys
        )
        
        # Изначально процесс не запущен
        assert adapter.is_process_running() is False
        
        # Мокаем запущенный процесс
        mock_process = Mock()
        mock_process.poll.return_value = None
        adapter.gpt_pilot_process = mock_process
        
        assert adapter.is_process_running() is True


class TestSamokoderGPTPilotRealAdapterErrorHandling:
    """Тесты обработки ошибок для SamokoderGPTPilotRealAdapter"""
    
    @pytest.mark.asyncio
    async def test_timeout_error_handling(self, mock_api_keys):
        """Тест обработки ошибки таймаута"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.side_effect = asyncio.TimeoutError("Timeout")
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.generate_code("Create a hello world function")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_json_decode_error_handling(self, mock_api_keys):
        """Тест обработки ошибки декодирования JSON"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'Invalid JSON response'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.generate_code("Create a hello world function")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_process_crash_handling(self, mock_api_keys):
        """Тест обработки краша процесса"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = -1  # Процесс завершился с ошибкой
            mock_process.stderr.readline.return_value = b'Process crashed'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            result = await adapter.generate_code("Create a hello world function")
            
            assert result is None


class TestSamokoderGPTPilotRealAdapterIntegration:
    """Интеграционные тесты для SamokoderGPTPilotRealAdapter"""
    
    @pytest.mark.asyncio
    async def test_full_code_generation_workflow(self, mock_api_keys):
        """Тест полного рабочего процесса генерации кода"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            
            # Мокаем различные ответы для разных операций
            responses = [
                b'{"status": "success", "message": "Project initialized"}',
                b'{"status": "success", "code": "def hello():\\n    print(\\"Hello World\\")"}',
                b'{"status": "success", "refactored_code": "def hello():\\n    print(\\"Hello World\\")"}',
                b'{"status": "success", "explanation": "This function prints hello world"}'
            ]
            
            mock_process.stdout.readline.side_effect = responses
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            # 1. Инициализируем проект
            init_result = await adapter.initialize_project()
            assert init_result is True
            
            # 2. Генерируем код
            code_result = await adapter.generate_code("Create a hello world function")
            assert code_result is not None
            assert "code" in code_result
            
            # 3. Рефакторим код
            refactor_result = await adapter.refactor_code(
                code_result["code"], 
                "Make it more robust"
            )
            assert refactor_result is not None
            assert "refactored_code" in refactor_result
            
            # 4. Объясняем код
            explain_result = await adapter.explain_code(refactor_result["refactored_code"])
            assert explain_result is not None
            assert "explanation" in explain_result
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, mock_api_keys):
        """Тест параллельных операций"""
        with patch('backend.services.gpt_pilot_real_adapter.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_process.stdout.readline.return_value = b'{"status": "success", "code": "print(\\"Hello\\")"}'
            mock_popen.return_value = mock_process
            
            adapter = SamokoderGPTPilotRealAdapter(
                project_id="test-project-123",
                user_id="test-user-456",
                user_api_keys=mock_api_keys
            )
            
            # Выполняем несколько операций параллельно
            tasks = [
                adapter.generate_code("Create function 1"),
                adapter.generate_code("Create function 2"),
                adapter.generate_code("Create function 3")
            ]
            
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 3
            for result in results:
                assert result is not None
                assert "code" in result
