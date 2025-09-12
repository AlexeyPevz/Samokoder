#!/usr/bin/env python3
"""
Финальные тесты для Project State Manager
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import asyncio
from backend.services.project_state_manager import ProjectStateManager, ProjectState, get_active_project, add_active_project, remove_active_project, is_project_active, project_context


class TestProjectStateManagerFinal:
    """Финальные тесты для ProjectStateManager"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.manager = ProjectStateManager(max_projects=10, idle_timeout=3600)
    
    def test_init(self):
        """Тест инициализации менеджера"""
        assert self.manager.max_projects == 10
        assert self.manager.idle_timeout == 3600
        assert len(self.manager._projects) == 0
        assert self.manager._initialized is False
    
    @pytest.mark.asyncio
    async def test_initialize_success(self):
        """Тест успешной инициализации"""
        with patch('asyncio.create_task') as mock_create_task:
            mock_task = Mock()
            mock_create_task.return_value = mock_task
            
            await self.manager.initialize()
            
            assert self.manager._initialized is True
            assert self.manager._cleanup_task == mock_task
            mock_create_task.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initialize_already_initialized(self):
        """Тест инициализации уже инициализированного менеджера"""
        self.manager._initialized = True
        with patch('asyncio.create_task') as mock_create_task:
            await self.manager.initialize()
            
            mock_create_task.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_add_project_success(self):
        """Тест успешного добавления проекта"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        result = await self.manager.add_project(project_id, user_id, pilot_wrapper)
        
        assert result is True
        assert project_id in self.manager._projects
        project_state = self.manager._projects[project_id]
        assert project_state.project_id == project_id
        assert project_state.user_id == user_id
        assert project_state.pilot_wrapper == pilot_wrapper
        assert project_state.is_active is True
    
    @pytest.mark.asyncio
    async def test_add_project_max_projects_reached(self):
        """Тест добавления проекта при достижении максимального количества"""
        # Заполняем менеджер до максимума
        for i in range(10):
            await self.manager.add_project(f"project{i}", f"user{i}", Mock())
        
        # Добавляем еще один проект
        result = await self.manager.add_project("new_project", "new_user", Mock())
        
        assert result is True
        assert "new_project" in self.manager._projects
        # Проверяем что один из старых проектов был удален
        assert len(self.manager._projects) <= 10
    
    @pytest.mark.asyncio
    async def test_get_project_success(self):
        """Тест успешного получения проекта"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        await self.manager.add_project(project_id, user_id, pilot_wrapper)
        
        result = await self.manager.get_project(project_id, user_id)
        
        assert result == pilot_wrapper
        # Проверяем что last_accessed обновился
        project_state = self.manager._projects[project_id]
        assert project_state.last_accessed > datetime.now() - timedelta(seconds=1)
    
    @pytest.mark.asyncio
    async def test_get_project_not_found(self):
        """Тест получения несуществующего проекта"""
        with patch.object(self.manager, '_load_project_from_db') as mock_load:
            mock_load.return_value = None
            
            result = await self.manager.get_project("nonexistent", "user123")
            assert result is None
            mock_load.assert_called_once_with("nonexistent", "user123")
    
    @pytest.mark.asyncio
    async def test_get_project_wrong_user(self):
        """Тест получения проекта с неправильным пользователем"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        await self.manager.add_project(project_id, user_id, pilot_wrapper)
        
        result = await self.manager.get_project(project_id, "wrong_user")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_remove_project_success(self):
        """Тест успешного удаления проекта"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        await self.manager.add_project(project_id, user_id, pilot_wrapper)
        
        result = await self.manager.remove_project(project_id, user_id)
        
        assert result is True
        assert project_id not in self.manager._projects
    
    @pytest.mark.asyncio
    async def test_remove_project_not_found(self):
        """Тест удаления несуществующего проекта"""
        result = await self.manager.remove_project("nonexistent", "user123")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_remove_project_wrong_user(self):
        """Тест удаления проекта с неправильным пользователем"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        await self.manager.add_project(project_id, user_id, pilot_wrapper)
        
        result = await self.manager.remove_project(project_id, "wrong_user")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_list_user_projects(self):
        """Тест получения списка проектов пользователя"""
        user_id = "user123"
        
        # Добавляем проекты для пользователя
        await self.manager.add_project("project1", user_id, Mock())
        await self.manager.add_project("project2", user_id, Mock())
        await self.manager.add_project("project3", "other_user", Mock())
        
        result = await self.manager.list_user_projects(user_id)
        
        assert len(result) == 2
        project_ids = [p["project_id"] for p in result]
        assert "project1" in project_ids
        assert "project2" in project_ids
        assert "project3" not in project_ids
    
    @pytest.mark.asyncio
    async def test_is_project_active_success(self):
        """Тест проверки активности проекта - успех"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        await self.manager.add_project(project_id, user_id, pilot_wrapper)
        
        result = await self.manager.is_project_active(project_id, user_id)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_project_active_not_found(self):
        """Тест проверки активности несуществующего проекта"""
        result = await self.manager.is_project_active("nonexistent", "user123")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_load_project_from_db_not_found(self):
        """Тест загрузки несуществующего проекта из базы данных"""
        project_id = "nonexistent"
        user_id = "user123"
        
        with patch('backend.services.project_state_manager.execute_supabase_operation') as mock_supabase:
            mock_supabase.return_value = Mock(data=None)
            
            result = await self.manager._load_project_from_db(project_id, user_id)
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_remove_oldest_project(self):
        """Тест удаления самого старого проекта"""
        # Добавляем несколько проектов с разным временем создания
        for i in range(3):
            await self.manager.add_project(f"project{i}", f"user{i}", Mock())
        
        # Ждем немного чтобы время создания отличалось
        await asyncio.sleep(0.01)
        
        initial_count = len(self.manager._projects)
        
        await self.manager._remove_oldest_project()
        
        assert len(self.manager._projects) == initial_count - 1
    
    @pytest.mark.asyncio
    async def test_cleanup_inactive_projects(self):
        """Тест очистки неактивных проектов"""
        # Добавляем проект и делаем его неактивным
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        await self.manager.add_project(project_id, user_id, pilot_wrapper)
        
        # Устанавливаем старое время доступа
        project_state = self.manager._projects[project_id]
        project_state.last_accessed = datetime.now() - timedelta(seconds=7200)  # 2 часа назад
        
        await self.manager._cleanup_inactive_projects()
        
        assert project_id not in self.manager._projects
    
    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Тест получения статистики"""
        # Добавляем несколько проектов
        await self.manager.add_project("project1", "user1", Mock())
        await self.manager.add_project("project2", "user1", Mock())
        await self.manager.add_project("project3", "user2", Mock())
        
        stats = await self.manager.get_stats()
        
        assert stats["total_projects"] == 3
        assert stats["max_projects"] == 10
        assert stats["idle_timeout"] == 3600
        assert "projects" in stats
        assert len(stats["projects"]) == 3


class TestProjectStateManagerGlobalFunctionsFinal:
    """Финальные тесты для глобальных функций Project State Manager"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.manager = ProjectStateManager()
    
    @pytest.mark.asyncio
    async def test_get_active_project_success(self):
        """Тест получения активного проекта - успех"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            await self.manager.add_project(project_id, user_id, pilot_wrapper)
            
            result = await get_active_project(project_id, user_id)
            
            assert result == pilot_wrapper
    
    @pytest.mark.asyncio
    async def test_get_active_project_not_found(self):
        """Тест получения несуществующего активного проекта"""
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            result = await get_active_project("nonexistent", "user123")
            assert result is None
    
    @pytest.mark.asyncio
    async def test_add_active_project_success(self):
        """Тест добавления активного проекта - успех"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            result = await add_active_project(project_id, user_id, pilot_wrapper)
            
            assert result is True
            assert project_id in self.manager._projects
    
    @pytest.mark.asyncio
    async def test_remove_active_project_success(self):
        """Тест удаления активного проекта - успех"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            await self.manager.add_project(project_id, user_id, pilot_wrapper)
            
            result = await remove_active_project(project_id, user_id)
            
            assert result is True
            assert project_id not in self.manager._projects
    
    @pytest.mark.asyncio
    async def test_remove_active_project_not_found(self):
        """Тест удаления несуществующего активного проекта"""
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            result = await remove_active_project("nonexistent", "user123")
            assert result is False
    
    @pytest.mark.asyncio
    async def test_is_project_active_success(self):
        """Тест проверки активности проекта - успех"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            await self.manager.add_project(project_id, user_id, pilot_wrapper)
            
            result = await is_project_active(project_id, user_id)
            assert result is True
    
    @pytest.mark.asyncio
    async def test_is_project_active_not_found(self):
        """Тест проверки активности несуществующего проекта"""
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            result = await is_project_active("nonexistent", "user123")
            assert result is False
    
    @pytest.mark.asyncio
    async def test_project_context_success(self):
        """Тест контекста проекта - успех"""
        project_id = "project123"
        user_id = "user123"
        pilot_wrapper = Mock()
        
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            await self.manager.add_project(project_id, user_id, pilot_wrapper)
            
            async with project_context(project_id, user_id) as context_pilot:
                assert context_pilot == pilot_wrapper
    
    @pytest.mark.asyncio
    async def test_project_context_not_found(self):
        """Тест контекста несуществующего проекта"""
        with patch('backend.services.project_state_manager.project_state_manager', self.manager):
            with pytest.raises(ValueError, match="Project nonexistent not found or not active"):
                async with project_context("nonexistent", "user123"):
                    pass