"""
Тесты для обработки ошибок в worker/main.py.

Критические риски:
- Worker получает невалидный project_id
- User не существует в БД
- Project не существует в БД
- API ключи отсутствуют или невалидны
- Encryption key отсутствует при расшифровке
- Orchestrator падает с исключением
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4, UUID

from worker.main import run_generation_task, ConsoleUI


class TestWorkerErrorHandling:
    """Тесты обработки ошибок в worker."""

    @pytest.mark.asyncio
    async def test_invalid_project_id_format(self):
        """Тест: невалидный формат project_id должен быть обработан."""
        ctx = MagicMock()
        
        # Invalid UUID format
        invalid_id = "not-a-uuid"
        
        with pytest.raises(ValueError):
            await run_generation_task(ctx, invalid_id, 1)

    @pytest.mark.asyncio
    async def test_user_not_found(self):
        """Тест: worker корректно обрабатывает отсутствие пользователя."""
        ctx = MagicMock()
        project_id = str(uuid4())
        user_id = 999999  # Non-existent user
        
        with patch('worker.main.SessionManager') as mock_session_manager:
            mock_db = AsyncMock()
            mock_db.get = AsyncMock(return_value=None)  # User not found
            mock_session_manager.return_value.get_session.return_value.__aenter__.return_value = mock_db
            
            result = await run_generation_task(ctx, project_id, user_id)
            
            # Should return early without crashing
            assert result is None

    @pytest.mark.asyncio
    async def test_project_not_found(self):
        """Тест: worker корректно обрабатывает отсутствие проекта."""
        ctx = MagicMock()
        project_id = str(uuid4())
        user_id = 1
        
        with patch('worker.main.SessionManager') as mock_session_manager:
            mock_db = AsyncMock()
            # Return user but not project
            mock_db.get = AsyncMock(side_effect=[MagicMock(id=user_id), None])
            mock_session_manager.return_value.get_session.return_value.__aenter__.return_value = mock_db
            
            result = await run_generation_task(ctx, project_id, user_id)
            
            # Should return early without crashing
            assert result is None

    @pytest.mark.asyncio
    async def test_missing_app_secret_key(self):
        """Тест: отсутствие APP_SECRET_KEY должно приводить к ошибке."""
        ctx = MagicMock()
        project_id = str(uuid4())
        user_id = 1
        
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.api_keys = {"openai": {"encrypted_key": "encrypted_value"}}
        mock_user.get_api_key_settings = MagicMock(return_value={})
        
        mock_project = MagicMock()
        mock_project.id = UUID(project_id)
        
        with patch('worker.main.SessionManager') as mock_session_manager:
            mock_db = AsyncMock()
            mock_db.get = AsyncMock(side_effect=[mock_user, mock_project])
            mock_session_manager.return_value.get_session.return_value.__aenter__.return_value = mock_db
            
            with patch('worker.main.get_config') as mock_config:
                mock_config.return_value.app_secret_key = None  # Missing key!
                
                with pytest.raises(Exception):  # Should raise ConfigError
                    await run_generation_task(ctx, project_id, user_id)

    @pytest.mark.asyncio
    async def test_orchestrator_exception_handling(self):
        """Тест: исключения в orchestrator должны логироваться."""
        ctx = MagicMock()
        project_id = str(uuid4())
        user_id = 1
        
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.api_keys = None
        
        mock_project = MagicMock()
        mock_project.id = UUID(project_id)
        
        with patch('worker.main.SessionManager') as mock_session_manager, \
             patch('worker.main.StateManager') as mock_state_manager, \
             patch('worker.main.Orchestrator') as mock_orchestrator_class:
            
            mock_db = AsyncMock()
            mock_db.get = AsyncMock(side_effect=[mock_user, mock_project])
            mock_session_manager.return_value.get_session.return_value.__aenter__.return_value = mock_db
            
            # StateManager setup
            mock_sm = AsyncMock()
            mock_sm.file_system = None
            mock_state_manager.return_value = mock_sm
            
            # Orchestrator throws exception
            mock_orchestrator = AsyncMock()
            mock_orchestrator.run = AsyncMock(side_effect=RuntimeError("Test error"))
            mock_orchestrator_class.return_value = mock_orchestrator
            
            result = await run_generation_task(ctx, project_id, user_id)
            
            # Should return with success=False
            assert result is not None
            assert result["success"] is False
            assert result["project_id"] == project_id

    @pytest.mark.asyncio
    async def test_cleanup_called_on_success(self):
        """Тест: cleanup вызывается даже при успехе."""
        ctx = MagicMock()
        project_id = str(uuid4())
        user_id = 1
        
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.api_keys = None
        
        mock_project = MagicMock()
        mock_project.id = UUID(project_id)
        
        mock_cleanup = AsyncMock()
        
        with patch('worker.main.SessionManager') as mock_session_manager, \
             patch('worker.main.StateManager') as mock_state_manager, \
             patch('worker.main.Orchestrator') as mock_orchestrator_class:
            
            mock_db = AsyncMock()
            mock_db.get = AsyncMock(side_effect=[mock_user, mock_project])
            mock_session_manager.return_value.get_session.return_value.__aenter__.return_value = mock_db
            
            # StateManager with cleanup
            mock_sm = AsyncMock()
            mock_sm.file_system = MagicMock()
            mock_sm.file_system.cleanup = mock_cleanup
            mock_state_manager.return_value = mock_sm
            
            # Orchestrator succeeds
            mock_orchestrator = AsyncMock()
            mock_orchestrator.run = AsyncMock(return_value=True)
            mock_orchestrator_class.return_value = mock_orchestrator
            
            result = await run_generation_task(ctx, project_id, user_id)
            
            # Cleanup should be called
            mock_cleanup.assert_called_once()
            assert result["success"] is True


class TestConsoleUI:
    """Тесты для ConsoleUI worker."""

    @pytest.mark.asyncio
    async def test_send_message_does_not_crash(self):
        """Тест: send_message не падает при любых параметрах."""
        ui = ConsoleUI()
        
        await ui.send_message("Test message")
        await ui.send_message("Test", source="test")
        await ui.send_message("Test", source=None, extra_param="value")

    @pytest.mark.asyncio
    async def test_ask_question_returns_cancelled(self):
        """Тест: ask_question всегда возвращает cancelled=True."""
        ui = ConsoleUI()
        
        result = await ui.ask_question("Test question?")
        assert result.cancelled is True
        
        result = await ui.ask_question("Another question?", default="yes")
        assert result.cancelled is True

    @pytest.mark.asyncio
    async def test_send_project_stage_with_invalid_stage(self):
        """Тест: send_project_stage обрабатывает невалидные данные."""
        ui = ConsoleUI()
        
        # Stage without 'name'
        await ui.send_project_stage({})
        
        # Stage with None name
        await ui.send_project_stage({"name": None})
        
        # Stage is None
        with pytest.raises(AttributeError):
            await ui.send_project_stage(None)
