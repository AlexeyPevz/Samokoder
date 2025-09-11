"""
Комплексные тесты для File Upload endpoints
Покрывают все основные функции и сценарии
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from fastapi import UploadFile
import io

from backend.api.file_upload import (
    upload_file, upload_multiple_files, get_file_info, delete_file
)
from backend.models.requests import FileUploadRequest
from backend.models.responses import FileUploadResponse
from backend.core.exceptions import ValidationError, NotFoundError


class TestFileUploadEndpoints:
    """Тесты для File Upload endpoints"""
    
    def test_upload_file_endpoint_exists(self):
        """Проверяем, что endpoint upload_file существует"""
        assert callable(upload_file)
    
    def test_upload_multiple_files_endpoint_exists(self):
        """Проверяем, что endpoint upload_multiple_files существует"""
        assert callable(upload_multiple_files)
    
    def test_get_file_info_endpoint_exists(self):
        """Проверяем, что endpoint get_file_info существует"""
        assert callable(get_file_info)
    
    def test_delete_file_endpoint_exists(self):
        """Проверяем, что endpoint delete_file существует"""
        assert callable(delete_file)


class TestFileUploadRequest:
    """Тесты для FileUploadRequest модели"""
    
    def test_file_upload_request_creation(self):
        """Проверяем создание FileUploadRequest"""
        request = FileUploadRequest(
            filename="test.txt",
            content_type="text/plain",
            size=1024,
            project_id="project123"
        )
        
        assert request.filename == "test.txt"
        assert request.content_type == "text/plain"
        assert request.size == 1024
        assert request.project_id == "project123"
    
    def test_file_upload_request_defaults(self):
        """Проверяем значения по умолчанию"""
        request = FileUploadRequest(
            filename="test.txt",
            content_type="text/plain",
            size=1024
        )
        
        assert request.project_id is None


class TestFileUploadResponse:
    """Тесты для FileUploadResponse модели"""
    
    def test_file_upload_response_creation(self):
        """Проверяем создание FileUploadResponse"""
        response = FileUploadResponse(
            file_id="file123",
            filename="test.txt",
            content_type="text/plain",
            size=1024,
            upload_time="2025-01-11T10:00:00Z",
            project_id="project123",
            status="uploaded"
        )
        
        assert response.file_id == "file123"
        assert response.filename == "test.txt"
        assert response.content_type == "text/plain"
        assert response.size == 1024
        assert response.upload_time == "2025-01-11T10:00:00Z"
        assert response.project_id == "project123"
        assert response.status == "uploaded"


class TestFileUploadSecurity:
    """Тесты для безопасности загрузки файлов"""
    
    def test_validate_file_type_allowed(self):
        """Тест валидации разрешенных типов файлов"""
        from backend.security.file_upload_security import validate_file
        
        # Создаем mock файл
        mock_file = MagicMock()
        mock_file.filename = "test.txt"
        mock_file.content_type = "text/plain"
        mock_file.size = 1024
        
        # Тест должен пройти без ошибок
        try:
            validate_file(mock_file)
            assert True  # Если дошли до этой строки, валидация прошла
        except ValidationError:
            pytest.fail("Valid file should not raise ValidationError")
    
    def test_validate_file_type_not_allowed(self):
        """Тест валидации неразрешенных типов файлов"""
        from backend.security.file_upload_security import validate_file
        
        # Создаем mock файл с неразрешенным типом
        mock_file = MagicMock()
        mock_file.filename = "test.exe"
        mock_file.content_type = "application/x-executable"
        mock_file.size = 1024
        
        # Тест должен вызвать ValidationError
        with pytest.raises(ValidationError):
            validate_file(mock_file)
    
    def test_validate_file_size_limit(self):
        """Тест валидации размера файла"""
        from backend.security.file_upload_security import validate_file
        
        # Создаем mock файл с превышением размера
        mock_file = MagicMock()
        mock_file.filename = "test.txt"
        mock_file.content_type = "text/plain"
        mock_file.size = 100 * 1024 * 1024  # 100MB
        
        # Тест должен вызвать ValidationError
        with pytest.raises(ValidationError):
            validate_file(mock_file)
    
    def test_validate_file_malicious_name(self):
        """Тест валидации подозрительных имен файлов"""
        from backend.security.file_upload_security import validate_file
        
        # Создаем mock файл с подозрительным именем
        mock_file = MagicMock()
        mock_file.filename = "../../../etc/passwd"
        mock_file.content_type = "text/plain"
        mock_file.size = 1024
        
        # Тест должен вызвать ValidationError
        with pytest.raises(ValidationError):
            validate_file(mock_file)


class TestFileUploadFunctions:
    """Тесты для функций загрузки файлов"""
    
    @pytest.mark.asyncio
    async def test_upload_file_success(self):
        """Тест успешной загрузки файла"""
        from backend.security.file_upload_security import save_file, scan_file_for_malware
        
        # Мокаем функции
        with patch('backend.security.file_upload_security.save_file') as mock_save, \
             patch('backend.security.file_upload_security.scan_file_for_malware') as mock_scan:
            
            mock_save.return_value = "file123"
            mock_scan.return_value = True
            
            # Создаем mock файл
            mock_file = MagicMock()
            mock_file.filename = "test.txt"
            mock_file.content_type = "text/plain"
            mock_file.size = 1024
            
            # Тестируем загрузку
            file_id = await save_file(mock_file, "project123")
            is_safe = await scan_file_for_malware(mock_file)
            
            assert file_id == "file123"
            assert is_safe is True
            mock_save.assert_called_once_with(mock_file, "project123")
            mock_scan.assert_called_once_with(mock_file)
    
    @pytest.mark.asyncio
    async def test_upload_file_malware_detected(self):
        """Тест обнаружения вредоносного файла"""
        from backend.security.file_upload_security import scan_file_for_malware
        
        with patch('backend.security.file_upload_security.scan_file_for_malware') as mock_scan:
            mock_scan.return_value = False
            
            # Создаем mock файл
            mock_file = MagicMock()
            mock_file.filename = "suspicious.txt"
            mock_file.content_type = "text/plain"
            mock_file.size = 1024
            
            # Тестируем сканирование
            is_safe = await scan_file_for_malware(mock_file)
            
            assert is_safe is False
            mock_scan.assert_called_once_with(mock_file)
    
    @pytest.mark.asyncio
    async def test_get_file_info_success(self):
        """Тест получения информации о файле"""
        from backend.security.file_upload_security import get_file_info
        
        with patch('backend.security.file_upload_security.get_file_info') as mock_get_info:
            mock_info = {
                "file_id": "file123",
                "filename": "test.txt",
                "content_type": "text/plain",
                "size": 1024,
                "upload_time": "2025-01-11T10:00:00Z",
                "project_id": "project123",
                "status": "uploaded"
            }
            mock_get_info.return_value = mock_info
            
            # Тестируем получение информации
            info = await get_file_info("file123")
            
            assert info["file_id"] == "file123"
            assert info["filename"] == "test.txt"
            assert info["content_type"] == "text/plain"
            assert info["size"] == 1024
            mock_get_info.assert_called_once_with("file123")
    
    @pytest.mark.asyncio
    async def test_get_file_info_not_found(self):
        """Тест получения информации о несуществующем файле"""
        from backend.security.file_upload_security import get_file_info
        
        with patch('backend.security.file_upload_security.get_file_info') as mock_get_info:
            mock_get_info.return_value = None
            
            # Тестируем получение информации о несуществующем файле
            info = await get_file_info("nonexistent")
            
            assert info is None
            mock_get_info.assert_called_once_with("nonexistent")
    
    @pytest.mark.asyncio
    async def test_delete_file_success(self):
        """Тест успешного удаления файла"""
        from backend.security.file_upload_security import delete_file
        
        with patch('backend.security.file_upload_security.delete_file') as mock_delete:
            mock_delete.return_value = True
            
            # Тестируем удаление файла
            result = await delete_file("file123")
            
            assert result is True
            mock_delete.assert_called_once_with("file123")
    
    @pytest.mark.asyncio
    async def test_delete_file_not_found(self):
        """Тест удаления несуществующего файла"""
        from backend.security.file_upload_security import delete_file
        
        with patch('backend.security.file_upload_security.delete_file') as mock_delete:
            mock_delete.return_value = False
            
            # Тестируем удаление несуществующего файла
            result = await delete_file("nonexistent")
            
            assert result is False
            mock_delete.assert_called_once_with("nonexistent")


class TestFileUploadValidation:
    """Тесты для валидации загрузки файлов"""
    
    def test_validate_file_extension(self):
        """Тест валидации расширения файла"""
        from backend.security.file_upload_security import validate_file
        
        # Разрешенные расширения
        allowed_extensions = [".txt", ".pdf", ".jpg", ".png", ".doc", ".docx"]
        
        for ext in allowed_extensions:
            mock_file = MagicMock()
            mock_file.filename = f"test{ext}"
            mock_file.content_type = "text/plain"
            mock_file.size = 1024
            
            try:
                validate_file(mock_file)
                assert True  # Валидация прошла
            except ValidationError:
                pytest.fail(f"File with extension {ext} should be allowed")
    
    def test_validate_file_extension_not_allowed(self):
        """Тест валидации неразрешенных расширений"""
        from backend.security.file_upload_security import validate_file
        
        # Неразрешенные расширения
        forbidden_extensions = [".exe", ".bat", ".cmd", ".scr", ".pif"]
        
        for ext in forbidden_extensions:
            mock_file = MagicMock()
            mock_file.filename = f"test{ext}"
            mock_file.content_type = "application/x-executable"
            mock_file.size = 1024
            
            with pytest.raises(ValidationError):
                validate_file(mock_file)
    
    def test_validate_file_content_type(self):
        """Тест валидации MIME типа"""
        from backend.security.file_upload_security import validate_file
        
        # Разрешенные MIME типы
        allowed_types = [
            "text/plain",
            "application/pdf",
            "image/jpeg",
            "image/png",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ]
        
        for content_type in allowed_types:
            mock_file = MagicMock()
            mock_file.filename = "test.txt"
            mock_file.content_type = content_type
            mock_file.size = 1024
            
            try:
                validate_file(mock_file)
                assert True  # Валидация прошла
            except ValidationError:
                pytest.fail(f"File with content type {content_type} should be allowed")
    
    def test_validate_file_content_type_not_allowed(self):
        """Тест валидации неразрешенных MIME типов"""
        from backend.security.file_upload_security import validate_file
        
        # Неразрешенные MIME типы
        forbidden_types = [
            "application/x-executable",
            "application/x-msdownload",
            "application/x-msdos-program",
            "application/x-winexe"
        ]
        
        for content_type in forbidden_types:
            mock_file = MagicMock()
            mock_file.filename = "test.exe"
            mock_file.content_type = content_type
            mock_file.size = 1024
            
            with pytest.raises(ValidationError):
                validate_file(mock_file)


class TestFileUploadErrorHandling:
    """Тесты для обработки ошибок при загрузке файлов"""
    
    @pytest.mark.asyncio
    async def test_upload_file_validation_error(self):
        """Тест обработки ValidationError при загрузке"""
        from backend.security.file_upload_security import validate_file
        
        # Создаем файл, который не пройдет валидацию
        mock_file = MagicMock()
        mock_file.filename = "test.exe"
        mock_file.content_type = "application/x-executable"
        mock_file.size = 1024
        
        with pytest.raises(ValidationError):
            validate_file(mock_file)
    
    @pytest.mark.asyncio
    async def test_upload_file_size_error(self):
        """Тест обработки ошибки размера файла"""
        from backend.security.file_upload_security import validate_file
        
        # Создаем файл с превышением размера
        mock_file = MagicMock()
        mock_file.filename = "test.txt"
        mock_file.content_type = "text/plain"
        mock_file.size = 200 * 1024 * 1024  # 200MB
        
        with pytest.raises(ValidationError):
            validate_file(mock_file)
    
    @pytest.mark.asyncio
    async def test_upload_file_name_error(self):
        """Тест обработки ошибки имени файла"""
        from backend.security.file_upload_security import validate_file
        
        # Создаем файл с подозрительным именем
        mock_file = MagicMock()
        mock_file.filename = "../../../etc/passwd"
        mock_file.content_type = "text/plain"
        mock_file.size = 1024
        
        with pytest.raises(ValidationError):
            validate_file(mock_file)


class TestFileUploadIntegration:
    """Интеграционные тесты для загрузки файлов"""
    
    @pytest.mark.asyncio
    async def test_file_upload_full_workflow(self):
        """Тест полного рабочего процесса загрузки файла"""
        from backend.security.file_upload_security import (
            validate_file, save_file, scan_file_for_malware, get_file_info, delete_file
        )
        
        # Мокаем все функции
        with patch('backend.security.file_upload_security.validate_file') as mock_validate, \
             patch('backend.security.file_upload_security.save_file') as mock_save, \
             patch('backend.security.file_upload_security.scan_file_for_malware') as mock_scan, \
             patch('backend.security.file_upload_security.get_file_info') as mock_get_info, \
             patch('backend.security.file_upload_security.delete_file') as mock_delete:
            
            # Настраиваем моки
            mock_validate.return_value = True
            mock_save.return_value = "file123"
            mock_scan.return_value = True
            mock_get_info.return_value = {
                "file_id": "file123",
                "filename": "test.txt",
                "content_type": "text/plain",
                "size": 1024,
                "upload_time": "2025-01-11T10:00:00Z",
                "project_id": "project123",
                "status": "uploaded"
            }
            mock_delete.return_value = True
            
            # Создаем mock файл
            mock_file = MagicMock()
            mock_file.filename = "test.txt"
            mock_file.content_type = "text/plain"
            mock_file.size = 1024
            
            # Выполняем полный рабочий процесс
            # 1. Валидация
            is_valid = await validate_file(mock_file)
            assert is_valid is True
            
            # 2. Сохранение
            file_id = await save_file(mock_file, "project123")
            assert file_id == "file123"
            
            # 3. Сканирование на вредоносность
            is_safe = await scan_file_for_malware(mock_file)
            assert is_safe is True
            
            # 4. Получение информации
            info = await get_file_info("file123")
            assert info["file_id"] == "file123"
            assert info["filename"] == "test.txt"
            
            # 5. Удаление
            deleted = await delete_file("file123")
            assert deleted is True
            
            # Проверяем, что все функции были вызваны
            mock_validate.assert_called_once_with(mock_file)
            mock_save.assert_called_once_with(mock_file, "project123")
            mock_scan.assert_called_once_with(mock_file)
            mock_get_info.assert_called_once_with("file123")
            mock_delete.assert_called_once_with("file123")
    
    @pytest.mark.asyncio
    async def test_file_upload_multiple_files(self):
        """Тест загрузки нескольких файлов"""
        from backend.security.file_upload_security import validate_file, save_file
        
        with patch('backend.security.file_upload_security.validate_file') as mock_validate, \
             patch('backend.security.file_upload_security.save_file') as mock_save:
            
            mock_validate.return_value = True
            mock_save.side_effect = ["file1", "file2", "file3"]
            
            # Создаем несколько mock файлов
            files = []
            for i in range(3):
                mock_file = MagicMock()
                mock_file.filename = f"test{i}.txt"
                mock_file.content_type = "text/plain"
                mock_file.size = 1024
                files.append(mock_file)
            
            # Загружаем все файлы
            file_ids = []
            for file in files:
                is_valid = await validate_file(file)
                assert is_valid is True
                
                file_id = await save_file(file, "project123")
                file_ids.append(file_id)
            
            assert file_ids == ["file1", "file2", "file3"]
            assert mock_validate.call_count == 3
            assert mock_save.call_count == 3