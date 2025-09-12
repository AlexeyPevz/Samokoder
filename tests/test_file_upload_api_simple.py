#!/usr/bin/env python3
"""
Упрощенные тесты для File Upload API
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from backend.api.file_upload import router


class TestFileUploadAPISimple:
    """Упрощенные тесты для File Upload API"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.client = TestClient(router)
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.file_upload_rate_limit')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.validate_file')
    @patch('backend.api.file_upload.save_file')
    @patch('backend.api.file_upload.scan_file_for_malware')
    @patch('backend.api.file_upload.create_error_context')
    def test_upload_file_success(self, mock_error_context, mock_scan, mock_save, 
                               mock_validate, mock_path_validation, mock_rate_limit, 
                               mock_current_user):
        """Тест успешной загрузки файла"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_rate_limit.return_value = {"limit": 100, "remaining": 99}
        mock_path_validation.return_value = True
        mock_validate.return_value = (True, "Valid file", "text/plain")
        mock_save.return_value = "/uploads/test.txt"
        mock_scan.return_value = True
        mock_error_context.return_value = Mock(severity="MEDIUM")
        
        # Подготовка файла для загрузки
        file_content = b"Test file content"
        files = {"file": ("test.txt", file_content, "text/plain")}
        data = {"project_id": "project123"}
        
        # Выполнение запроса
        response = self.client.post("/upload", files=files, data=data)
        
        # Проверки
        assert response.status_code == 200
        response_data = response.json()
        assert "file_path" in response_data
        assert response_data["file_path"] == "/uploads/test.txt"
        
        # Проверка вызовов моков
        mock_path_validation.assert_called_once_with("project123")
        mock_validate.assert_called_once()
        mock_save.assert_called_once()
        mock_scan.assert_called_once()
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.file_upload_rate_limit')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.create_error_context')
    def test_upload_file_invalid_project_id(self, mock_error_context, mock_path_validation, 
                                          mock_rate_limit, mock_current_user):
        """Тест загрузки файла с невалидным project_id"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_rate_limit.return_value = {"limit": 100, "remaining": 99}
        mock_path_validation.return_value = False
        mock_error_context.return_value = Mock(severity="MEDIUM")
        
        # Подготовка файла для загрузки
        file_content = b"Test file content"
        files = {"file": ("test.txt", file_content, "text/plain")}
        data = {"project_id": "../../invalid"}
        
        # Выполнение запроса
        response = self.client.post("/upload", files=files, data=data)
        
        # Проверки
        assert response.status_code == 400
        response_data = response.json()
        assert response_data["detail"] == "Invalid project ID"
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.file_upload_rate_limit')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.validate_file')
    @patch('backend.api.file_upload.create_error_context')
    def test_upload_file_invalid_file(self, mock_error_context, mock_validate, 
                                    mock_path_validation, mock_rate_limit, mock_current_user):
        """Тест загрузки невалидного файла"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_rate_limit.return_value = {"limit": 100, "remaining": 99}
        mock_path_validation.return_value = True
        mock_validate.return_value = (False, "Invalid file type", None)
        mock_error_context.return_value = Mock(severity="MEDIUM")
        
        # Подготовка файла для загрузки
        file_content = b"Test file content"
        files = {"file": ("test.exe", file_content, "application/octet-stream")}
        data = {"project_id": "project123"}
        
        # Выполнение запроса
        response = self.client.post("/upload", files=files, data=data)
        
        # Проверки
        assert response.status_code == 400
        response_data = response.json()
        assert response_data["detail"] == "Invalid file type"
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.file_upload_rate_limit')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.validate_file')
    @patch('backend.api.file_upload.save_file')
    @patch('backend.api.file_upload.scan_file_for_malware')
    @patch('backend.api.file_upload.create_error_context')
    def test_upload_file_malware_detected(self, mock_error_context, mock_scan, mock_save, 
                                        mock_validate, mock_path_validation, mock_rate_limit, 
                                        mock_current_user):
        """Тест загрузки файла с обнаруженным вредоносным кодом"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_rate_limit.return_value = {"limit": 100, "remaining": 99}
        mock_path_validation.return_value = True
        mock_validate.return_value = (True, "Valid file", "text/plain")
        mock_save.return_value = "/uploads/test.txt"
        mock_scan.return_value = False  # Вредоносный код обнаружен
        mock_error_context.return_value = Mock(severity="MEDIUM")
        
        # Подготовка файла для загрузки
        file_content = b"Test file content"
        files = {"file": ("test.txt", file_content, "text/plain")}
        data = {"project_id": "project123"}
        
        # Выполнение запроса
        response = self.client.post("/upload", files=files, data=data)
        
        # Проверки
        assert response.status_code == 400
        response_data = response.json()
        assert "malware" in response_data["detail"].lower()
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.file_upload_rate_limit')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.validate_file')
    @patch('backend.api.file_upload.save_file')
    @patch('backend.api.file_upload.scan_file_for_malware')
    @patch('backend.api.file_upload.create_error_context')
    @patch('backend.api.file_upload.handle_generic_error')
    def test_upload_file_server_error(self, mock_handle_error, mock_error_context, mock_scan, 
                                    mock_save, mock_validate, mock_path_validation, 
                                    mock_rate_limit, mock_current_user):
        """Тест загрузки файла с серверной ошибкой"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_rate_limit.return_value = {"limit": 100, "remaining": 99}
        mock_path_validation.return_value = True
        mock_validate.return_value = (True, "Valid file", "text/plain")
        mock_save.side_effect = Exception("Database error")
        mock_error_context.return_value = Mock(severity="MEDIUM")
        mock_handle_error.return_value = JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )
        
        # Подготовка файла для загрузки
        file_content = b"Test file content"
        files = {"file": ("test.txt", file_content, "text/plain")}
        data = {"project_id": "project123"}
        
        # Выполнение запроса
        response = self.client.post("/upload", files=files, data=data)
        
        # Проверки
        assert response.status_code == 500
        response_data = response.json()
        assert response_data["detail"] == "Internal server error"
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.file_upload_rate_limit')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.validate_file')
    @patch('backend.api.file_upload.save_file')
    @patch('backend.api.file_upload.scan_file_for_malware')
    @patch('backend.api.file_upload.create_error_context')
    def test_upload_multiple_files_success(self, mock_error_context, mock_scan, mock_save, 
                                         mock_validate, mock_path_validation, mock_rate_limit, 
                                         mock_current_user):
        """Тест успешной загрузки нескольких файлов"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_rate_limit.return_value = {"limit": 100, "remaining": 99}
        mock_path_validation.return_value = True
        mock_validate.return_value = (True, "Valid file", "text/plain")
        mock_save.return_value = "/uploads/test.txt"
        mock_scan.return_value = True
        mock_error_context.return_value = Mock(severity="MEDIUM")
        
        # Подготовка файлов для загрузки
        file1_content = b"Test file 1 content"
        file2_content = b"Test file 2 content"
        files = [
            ("files", ("test1.txt", file1_content, "text/plain")),
            ("files", ("test2.txt", file2_content, "text/plain"))
        ]
        data = {"project_id": "project123"}
        
        # Выполнение запроса
        response = self.client.post("/upload-multiple", files=files, data=data)
        
        # Проверки
        assert response.status_code == 200
        response_data = response.json()
        assert isinstance(response_data, list)
        assert len(response_data) == 2
        assert all("file_path" in item for item in response_data)
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.get_file_info')
    @patch('backend.api.file_upload.create_error_context')
    def test_get_file_info_success(self, mock_error_context, mock_get_info, 
                                 mock_path_validation, mock_current_user):
        """Тест успешного получения информации о файле"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_path_validation.return_value = True
        mock_get_info.return_value = {
            "filename": "test.txt",
            "file_path": "/uploads/test.txt",
            "size": 1024,
            "mime_type": "text/plain",
            "created_at": "2023-01-01T00:00:00Z",
            "modified_at": "2023-01-01T00:00:00Z",
            "extension": ".txt"
        }
        mock_error_context.return_value = Mock(severity="LOW")
        
        # Выполнение запроса
        response = self.client.get("/info/uploads/test.txt")
        
        # Проверки
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["file_info"]["file_path"] == "/uploads/test.txt"
        assert response_data["file_info"]["size"] == 1024
        assert response_data["file_info"]["mime_type"] == "text/plain"
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.get_file_info')
    @patch('backend.api.file_upload.create_error_context')
    def test_get_file_info_not_found(self, mock_error_context, mock_get_info, 
                                   mock_path_validation, mock_current_user):
        """Тест получения информации о несуществующем файле"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_path_validation.return_value = True
        mock_get_info.return_value = None
        mock_error_context.return_value = Mock(severity="LOW")
        
        # Выполнение запроса
        response = self.client.get("/info/uploads/nonexistent.txt")
        
        # Проверки
        assert response.status_code == 404
        response_data = response.json()
        assert "not found" in response_data["detail"].lower()
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.delete_file')
    @patch('backend.api.file_upload.create_error_context')
    def test_delete_file_success(self, mock_error_context, mock_delete, 
                               mock_path_validation, mock_current_user):
        """Тест успешного удаления файла"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_path_validation.return_value = True
        mock_delete.return_value = True
        mock_error_context.return_value = Mock(severity="MEDIUM")
        
        # Выполнение запроса
        response = self.client.delete("/delete/uploads/test.txt")
        
        # Проверки
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["message"] == "File deleted successfully"
    
    @patch('backend.api.file_upload.get_current_user')
    @patch('backend.api.file_upload.validate_path_traversal')
    @patch('backend.api.file_upload.delete_file')
    @patch('backend.api.file_upload.create_error_context')
    def test_delete_file_not_found(self, mock_error_context, mock_delete, 
                                 mock_path_validation, mock_current_user):
        """Тест удаления несуществующего файла"""
        # Настройка моков
        mock_current_user.return_value = {"id": "user123", "email": "test@example.com"}
        mock_path_validation.return_value = True
        mock_delete.return_value = False
        mock_error_context.return_value = Mock(severity="MEDIUM")
        
        # Выполнение запроса
        response = self.client.delete("/delete/uploads/nonexistent.txt")
        
        # Проверки
        assert response.status_code == 404
        response_data = response.json()
        assert "not found" in response_data["detail"].lower()