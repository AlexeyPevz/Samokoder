"""
P0: Регрессионные тесты управления проектами
Критические тесты, блокирующие мёрж до зелёного прогона
"""

import pytest
import json
import uuid
import os
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from backend.main import app
from backend.auth.dependencies import get_current_user

client = TestClient(app)

# Тестовые данные
TEST_USER = {
    "id": "test_user_123",
    "email": "test@example.com",
    "full_name": "Test User"
}

class TestProjectCreationFlow:
    """P0: Критические тесты создания проектов"""
    
    def test_project_creation_success(self):
        """P0: Успешное создание проекта"""
        project_data = {
            "name": "Test Project",
            "description": "Test project description",
            "ai_config": {"model": "deepseek/deepseek-v3"},
            "tech_stack": {"frontend": "React", "backend": "FastAPI"}
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager, \
             patch('backend.main.SamokoderGPTPilot') as mock_pilot, \
             patch('os.makedirs') as mock_makedirs:
            
            # Мокаем аутентификацию
            mock_auth.return_value = TEST_USER
            
            # Мокаем Supabase
            mock_client = MagicMock()
            mock_manager.get_client.return_value = mock_client
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[{"id": "test_key_123", "provider_name": "openrouter", "api_key_encrypted": "encrypted_key"}]
            ))
            
            # Мокаем GPT Pilot
            mock_pilot_instance = MagicMock()
            mock_pilot_instance.initialize_project = AsyncMock(return_value={
                "status": "success",
                "workspace": "workspaces/test_user_123/test_project_123"
            })
            mock_pilot.return_value = mock_pilot_instance
            
            response = client.post("/api/projects", json=project_data)
            
            # Проверяем успешное создание
            assert response.status_code == 200
            data = response.json()
            assert "project_id" in data
            assert data["status"] == "draft"
            assert "message" in data
            assert "workspace" in data
    
    def test_project_creation_validation(self):
        """P0: Валидация данных при создании проекта"""
        # Тест с пустыми данными
        response = client.post("/api/projects", json={})
        assert response.status_code == 400
        
        # Тест с невалидными данными
        invalid_data = {
            "name": "",  # Пустое имя
            "description": None  # None вместо строки
        }
        
        with patch('backend.main.get_current_user') as mock_auth:
            mock_auth.return_value = TEST_USER
            
            response = client.post("/api/projects", json=invalid_data)
            assert response.status_code == 400
    
    def test_project_creation_duplicate_name(self):
        """P0: Создание проекта с дублирующимся именем"""
        project_data = {
            "name": "Duplicate Project",
            "description": "Test project description"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager, \
             patch('backend.main.SamokoderGPTPilot') as mock_pilot:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем существующий проект с таким же именем
            mock_manager.execute_supabase_operation = AsyncMock(side_effect=[
                MagicMock(data=[{"id": "existing_project", "name": "Duplicate Project"}]),  # Проверка существования
                MagicMock(data=[])  # API ключи
            ])
            
            mock_pilot_instance = MagicMock()
            mock_pilot_instance.initialize_project = AsyncMock(return_value={
                "status": "error",
                "message": "Project with this name already exists"
            })
            mock_pilot.return_value = mock_pilot_instance
            
            response = client.post("/api/projects", json=project_data)
            
            # Должен быть отклонён из-за дублирующегося имени
            assert response.status_code == 400
    
    def test_project_creation_workspace_creation(self):
        """P0: Создание workspace директории"""
        project_data = {
            "name": "Workspace Test Project",
            "description": "Testing workspace creation"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager, \
             patch('backend.main.SamokoderGPTPilot') as mock_pilot, \
             patch('os.makedirs') as mock_makedirs:
            
            mock_auth.return_value = TEST_USER
            
            mock_client = MagicMock()
            mock_manager.get_client.return_value = mock_client
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(data=[]))
            
            mock_pilot_instance = MagicMock()
            mock_pilot_instance.initialize_project = AsyncMock(return_value={
                "status": "success",
                "workspace": "workspaces/test_user_123/workspace_test_project"
            })
            mock_pilot.return_value = mock_pilot_instance
            
            response = client.post("/api/projects", json=project_data)
            
            # Проверяем, что директория была создана
            mock_makedirs.assert_called()
            assert response.status_code == 200

class TestProjectListingFlow:
    """P0: Критические тесты получения списка проектов"""
    
    def test_project_listing_success(self):
        """P0: Успешное получение списка проектов"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем список проектов
            mock_projects = [
                {
                    "id": "project_1",
                    "name": "Project 1",
                    "description": "Description 1",
                    "user_id": "test_user_123",
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat()
                },
                {
                    "id": "project_2",
                    "name": "Project 2",
                    "description": "Description 2",
                    "user_id": "test_user_123",
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat()
                }
            ]
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=mock_projects
            ))
            
            response = client.get("/api/projects")
            
            # Проверяем успешное получение списка
            assert response.status_code == 200
            data = response.json()
            assert "projects" in data
            assert "total_count" in data
            assert len(data["projects"]) == 2
            assert data["total_count"] == 2
    
    def test_project_listing_empty(self):
        """P0: Получение пустого списка проектов"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем пустой список
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.get("/api/projects")
            
            # Проверяем пустой список
            assert response.status_code == 200
            data = response.json()
            assert "projects" in data
            assert "total_count" in data
            assert len(data["projects"]) == 0
            assert data["total_count"] == 0
    
    def test_project_listing_user_isolation(self):
        """P0: Изоляция проектов между пользователями"""
        other_user = {
            "id": "other_user_123",
            "email": "other@example.com",
            "full_name": "Other User"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = other_user
            
            # Мокаем пустой список (пользователь не должен видеть чужие проекты)
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.get("/api/projects")
            
            # Проверяем, что пользователь не видит чужие проекты
            assert response.status_code == 200
            data = response.json()
            assert len(data["projects"]) == 0

class TestProjectAccessFlow:
    """P0: Критические тесты доступа к проектам"""
    
    def test_project_access_success(self):
        """P0: Успешный доступ к проекту"""
        project_id = "test_project_123"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем проект
            mock_project = {
                "id": project_id,
                "name": "Test Project",
                "description": "Test description",
                "user_id": "test_user_123",
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=mock_project
            ))
            
            response = client.get(f"/api/projects/{project_id}")
            
            # Проверяем успешный доступ
            assert response.status_code == 200
            data = response.json()
            assert "project" in data
            assert data["project"]["id"] == project_id
            assert data["project"]["name"] == "Test Project"
    
    def test_project_access_not_found(self):
        """P0: Доступ к несуществующему проекту"""
        project_id = "nonexistent_project"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем отсутствие проекта
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=None
            ))
            
            response = client.get(f"/api/projects/{project_id}")
            
            # Проверяем ошибку 404
            assert response.status_code == 404
    
    def test_project_access_unauthorized(self):
        """P0: Неавторизованный доступ к проекту"""
        project_id = "other_user_project"
        other_user = {
            "id": "other_user_123",
            "email": "other@example.com"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = other_user
            
            # Мокаем отсутствие проекта (пользователь не имеет доступа)
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=None
            ))
            
            response = client.get(f"/api/projects/{project_id}")
            
            # Проверяем ошибку 404 (не 403, так как проект "не найден")
            assert response.status_code == 404

class TestProjectUpdateFlow:
    """P0: Критические тесты обновления проектов"""
    
    def test_project_update_success(self):
        """P0: Успешное обновление проекта"""
        project_id = "test_project_123"
        update_data = {
            "name": "Updated Project Name",
            "description": "Updated description"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем существующий проект и успешное обновление
            mock_manager.execute_supabase_operation = AsyncMock(side_effect=[
                MagicMock(data=[{"id": project_id, "user_id": "test_user_123"}]),  # Проверка существования
                MagicMock(data=[{**update_data, "id": project_id, "user_id": "test_user_123"}])  # Обновление
            ])
            
            response = client.put(f"/api/projects/{project_id}", json=update_data)
            
            # Проверяем успешное обновление
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "Updated Project Name"
            assert data["description"] == "Updated description"
    
    def test_project_update_not_found(self):
        """P0: Обновление несуществующего проекта"""
        project_id = "nonexistent_project"
        update_data = {
            "name": "Updated Name"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем отсутствие проекта
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=None
            ))
            
            response = client.put(f"/api/projects/{project_id}", json=update_data)
            
            # Проверяем ошибку 404
            assert response.status_code == 404
    
    def test_project_update_unauthorized(self):
        """P0: Неавторизованное обновление проекта"""
        project_id = "other_user_project"
        update_data = {
            "name": "Hacked Name"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем отсутствие проекта (пользователь не имеет доступа)
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=None
            ))
            
            response = client.put(f"/api/projects/{project_id}", json=update_data)
            
            # Проверяем ошибку 404
            assert response.status_code == 404

class TestProjectDeletionFlow:
    """P0: Критические тесты удаления проектов"""
    
    def test_project_deletion_success(self):
        """P0: Успешное удаление проекта"""
        project_id = "test_project_123"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем существующий проект и успешное удаление
            mock_manager.execute_supabase_operation = AsyncMock(side_effect=[
                MagicMock(data=[{"id": project_id, "user_id": "test_user_123"}]),  # Проверка существования
                MagicMock(data=[{"id": project_id, "is_active": False}])  # Soft delete
            ])
            
            response = client.delete(f"/api/projects/{project_id}")
            
            # Проверяем успешное удаление
            assert response.status_code == 200
            data = response.json()
            assert "message" in data
    
    def test_project_deletion_not_found(self):
        """P0: Удаление несуществующего проекта"""
        project_id = "nonexistent_project"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем отсутствие проекта
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=None
            ))
            
            response = client.delete(f"/api/projects/{project_id}")
            
            # Проверяем ошибку 404
            assert response.status_code == 404
    
    def test_project_deletion_unauthorized(self):
        """P0: Неавторизованное удаление проекта"""
        project_id = "other_user_project"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем отсутствие проекта (пользователь не имеет доступа)
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=None
            ))
            
            response = client.delete(f"/api/projects/{project_id}")
            
            # Проверяем ошибку 404
            assert response.status_code == 404

class TestProjectFileOperations:
    """P0: Критические тесты работы с файлами проектов"""
    
    def test_project_files_listing(self):
        """P0: Получение списка файлов проекта"""
        project_id = "test_project_123"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_active_project') as mock_get_project, \
             patch('backend.main.load_project_to_memory') as mock_load:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем активный проект
            mock_pilot = MagicMock()
            mock_pilot.get_project_files = AsyncMock(return_value={
                "files": [
                    {"name": "main.py", "type": "file", "size": 1024},
                    {"name": "requirements.txt", "type": "file", "size": 512}
                ]
            })
            mock_get_project.return_value = mock_pilot
            
            response = client.get(f"/api/projects/{project_id}/files")
            
            # Проверяем успешное получение файлов
            assert response.status_code == 200
            data = response.json()
            assert "files" in data
            assert "project_id" in data
            assert len(data["files"]) == 2
    
    def test_project_file_content(self):
        """P0: Получение содержимого файла проекта"""
        project_id = "test_project_123"
        file_path = "main.py"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_active_project') as mock_get_project, \
             patch('backend.main.load_project_to_memory') as mock_load:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем активный проект
            mock_pilot = MagicMock()
            mock_pilot.get_file_content.return_value = "print('Hello, World!')"
            mock_get_project.return_value = mock_pilot
            
            response = client.get(f"/api/projects/{project_id}/files/{file_path}")
            
            # Проверяем успешное получение содержимого
            assert response.status_code == 200
            data = response.json()
            assert "content" in data
            assert "file_path" in data
            assert "size" in data
            assert data["content"] == "print('Hello, World!')"
    
    def test_project_file_not_found(self):
        """P0: Получение несуществующего файла"""
        project_id = "test_project_123"
        file_path = "nonexistent.py"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_active_project') as mock_get_project, \
             patch('backend.main.load_project_to_memory') as mock_load:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем активный проект
            mock_pilot = MagicMock()
            mock_pilot.get_file_content.side_effect = FileNotFoundError("File not found")
            mock_get_project.return_value = mock_pilot
            
            response = client.get(f"/api/projects/{project_id}/files/{file_path}")
            
            # Проверяем ошибку 404
            assert response.status_code == 404

class TestProjectExportFlow:
    """P0: Критические тесты экспорта проектов"""
    
    def test_project_export_success(self):
        """P0: Успешный экспорт проекта"""
        project_id = "test_project_123"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_active_project') as mock_get_project, \
             patch('backend.main.load_project_to_memory') as mock_load:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем активный проект
            mock_pilot = MagicMock()
            mock_pilot.create_zip_export.return_value = "/tmp/test_project.zip"
            mock_get_project.return_value = mock_pilot
            
            response = client.post(f"/api/projects/{project_id}/export")
            
            # Проверяем успешный экспорт
            assert response.status_code == 200
            assert response.headers["content-type"] == "application/zip"
            assert "samokoder_project_" in response.headers["content-disposition"]
    
    def test_project_export_not_found(self):
        """P0: Экспорт несуществующего проекта"""
        project_id = "nonexistent_project"
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_active_project') as mock_get_project, \
             patch('backend.main.load_project_to_memory') as mock_load:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем отсутствие проекта
            mock_get_project.return_value = None
            mock_load.return_value = None
            
            response = client.post(f"/api/projects/{project_id}/export")
            
            # Проверяем ошибку 404
            assert response.status_code == 404

if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, "-v", "--tb=short", "-x"])