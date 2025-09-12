"""
Комплексные тесты для File Upload API
Покрытие всех эндпоинтов и сценариев ошибок
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient
from io import BytesIO
import uuid

from backend.api.file_upload import router
from backend.models.responses import FileUploadResponse, FileInfoResponse
from backend.security.secure_error_handler import ErrorSeverity


class TestFileUploadEndpoints:
    """Тесты для всех эндпоинтов загрузки файлов"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": str(uuid.uuid4()), "email": "test@example.com"}
    
    @pytest.fixture
    def mock_upload_file(self):
        file_content = b"test file content"
        file_obj = UploadFile(
            filename="test.txt",
            file=BytesIO(file_content),
            size=len(file_content)
        )
        return file_obj
    
    @pytest.fixture
    def mock_multiple_upload_files(self):
        files = []
        for i in range(3):
            file_content = f"test file content {i}".encode()
            file_obj = UploadFile(
                filename=f"test{i}.txt",
                file=BytesIO(file_content),
                size=len(file_content)
            )
            files.append(file_obj)
        return files
    
    @pytest.fixture
    def mock_file_info(self):
        return {
            "filename": "test.txt",
            "size": 1024,
            "mime_type": "text/plain",
            "created_at": "2024-01-01T00:00:00Z",
            "modified_at": "2024-01-01T00:00:00Z",
            "extension": "txt"
        }
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"remaining": 100, "reset_time": 3600}
    
    # === SINGLE FILE UPLOAD TESTS ===
    
    @pytest.mark.asyncio
    async def test_upload_file_success(self, mock_current_user, mock_upload_file, 
                                     mock_file_info, mock_rate_limit):
        """Тест успешной загрузки файла"""
        project_id = "test-project-123"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(True, "File saved", "/path/to/file")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(True, "Clean file")), \
             patch('backend.api.file_upload.get_file_info', return_value=mock_file_info), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_file
            
            # Мокаем Request объект
            mock_request = Mock()
            
            result = await upload_file(
                mock_request, 
                mock_upload_file, 
                project_id, 
                mock_current_user, 
                mock_rate_limit
            )
            
            assert isinstance(result, FileUploadResponse)
            assert result.success is True
            assert result.message == "File uploaded successfully"
            assert result.filename == "test.txt"
            assert result.mime_type == "text/plain"
            assert result.size == 17  # len("test file content")
    
    @pytest.mark.asyncio
    async def test_upload_file_invalid_project_id(self, mock_current_user, mock_upload_file, 
                                                 mock_rate_limit):
        """Тест загрузки файла с невалидным project_id"""
        project_id = "../invalid/path"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_file
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request, 
                    mock_upload_file, 
                    project_id, 
                    mock_current_user, 
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == 400
            assert "Invalid project ID" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_upload_file_validation_failed(self, mock_current_user, mock_upload_file, 
                                                mock_rate_limit):
        """Тест загрузки файла с неудачной валидацией"""
        project_id = "test-project-123"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(False, "Invalid file type", None)), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_file
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request, 
                    mock_upload_file, 
                    project_id, 
                    mock_current_user, 
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == 400
            assert "Invalid file type" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_upload_file_save_failed(self, mock_current_user, mock_upload_file, 
                                          mock_rate_limit):
        """Тест загрузки файла с неудачным сохранением"""
        project_id = "test-project-123"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(False, "Save failed", None)), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_file
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request, 
                    mock_upload_file, 
                    project_id, 
                    mock_current_user, 
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == 500
            assert "Save failed" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_upload_file_malware_detected(self, mock_current_user, mock_upload_file, 
                                               mock_rate_limit):
        """Тест загрузки файла с обнаруженным malware"""
        project_id = "test-project-123"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(True, "File saved", "/path/to/file")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(False, "Malware detected")), \
             patch('backend.api.file_upload.delete_file', return_value=True), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_file
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request, 
                    mock_upload_file, 
                    project_id, 
                    mock_current_user, 
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == 400
            assert "File rejected: Malware detected" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_upload_file_general_exception(self, mock_current_user, mock_upload_file, 
                                                mock_rate_limit):
        """Тест загрузки файла с общим исключением"""
        project_id = "test-project-123"
        
        with patch('backend.api.file_upload.validate_path_traversal', side_effect=Exception("Unexpected error")), \
             patch('backend.api.file_upload.create_error_context') as mock_context, \
             patch('backend.api.file_upload.handle_generic_error', return_value=Mock()) as mock_error_handler:
            
            from backend.api.file_upload import upload_file
            
            mock_request = Mock()
            
            result = await upload_file(
                mock_request, 
                mock_upload_file, 
                project_id, 
                mock_current_user, 
                mock_rate_limit
            )
            
            # Должен вызвать обработчик ошибок
            mock_error_handler.assert_called_once()
    
    # === MULTIPLE FILES UPLOAD TESTS ===
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_success(self, mock_current_user, mock_multiple_upload_files, 
                                                mock_file_info, mock_rate_limit):
        """Тест успешной загрузки нескольких файлов"""
        project_id = "test-project-123"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(True, "File saved", "/path/to/file")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(True, "Clean file")), \
             patch('backend.api.file_upload.get_file_info', return_value=mock_file_info), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_multiple_files
            
            mock_request = Mock()
            
            results = await upload_multiple_files(
                mock_request, 
                mock_multiple_upload_files, 
                project_id, 
                mock_current_user, 
                mock_rate_limit
            )
            
            assert len(results) == 3
            for result in results:
                assert isinstance(result, FileUploadResponse)
                assert result.success is True
                assert "uploaded successfully" in result.message
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_too_many(self, mock_current_user, mock_rate_limit):
        """Тест загрузки слишком большого количества файлов"""
        project_id = "test-project-123"
        
        # Создаем 11 файлов (больше лимита в 10)
        files = []
        for i in range(11):
            file_content = f"test file content {i}".encode()
            file_obj = UploadFile(
                filename=f"test{i}.txt",
                file=BytesIO(file_content),
                size=len(file_content)
            )
            files.append(file_obj)
        
        with patch('backend.api.file_upload.create_error_context') as mock_context:
            
            from backend.api.file_upload import upload_multiple_files
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_multiple_files(
                    mock_request, 
                    files, 
                    project_id, 
                    mock_current_user, 
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == 400
            assert "Too many files" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_invalid_project_id(self, mock_current_user, 
                                                           mock_multiple_upload_files, 
                                                           mock_rate_limit):
        """Тест загрузки нескольких файлов с невалидным project_id"""
        project_id = "../invalid/path"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_multiple_files
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_multiple_files(
                    mock_request, 
                    mock_multiple_upload_files, 
                    project_id, 
                    mock_current_user, 
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == 400
            assert "Invalid project ID" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_mixed_results(self, mock_current_user, mock_rate_limit):
        """Тест загрузки нескольких файлов со смешанными результатами"""
        project_id = "test-project-123"
        
        # Создаем файлы с разными результатами
        files = []
        for i in range(3):
            file_content = f"test file content {i}".encode()
            file_obj = UploadFile(
                filename=f"test{i}.txt",
                file=BytesIO(file_content),
                size=len(file_content)
            )
            files.append(file_obj)
        
        def mock_validate_file(content, filename):
            # Первый файл - валидный, второй - невалидный, третий - валидный
            if "test0.txt" in filename:
                return (True, "Valid file", "text/plain")
            elif "test1.txt" in filename:
                return (False, "Invalid file", None)
            else:
                return (True, "Valid file", "text/plain")
        
        def mock_save_file(content, filename, user_id, project_id):
            # Третий файл не сохраняется
            if "test2.txt" in filename:
                return (False, "Save failed", None)
            else:
                return (True, "File saved", f"/path/to/{filename}")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', side_effect=mock_validate_file), \
             patch('backend.api.file_upload.save_file', side_effect=mock_save_file), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(True, "Clean file")), \
             patch('backend.api.file_upload.get_file_info', return_value={"filename": "test.txt", "size": 1024, "mime_type": "text/plain", "created_at": "2024-01-01T00:00:00Z", "modified_at": "2024-01-01T00:00:00Z", "extension": "txt"}), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import upload_multiple_files
            
            mock_request = Mock()
            
            results = await upload_multiple_files(
                mock_request, 
                files, 
                project_id, 
                mock_current_user, 
                mock_rate_limit
            )
            
            assert len(results) == 3
            assert results[0].success is True  # Первый файл успешно загружен
            assert results[1].success is False  # Второй файл не прошел валидацию
            assert results[2].success is False  # Третий файл не сохранился
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_general_exception(self, mock_current_user, 
                                                          mock_multiple_upload_files, 
                                                          mock_rate_limit):
        """Тест загрузки нескольких файлов с общим исключением"""
        project_id = "test-project-123"
        
        with patch('backend.api.file_upload.validate_path_traversal', side_effect=Exception("Unexpected error")), \
             patch('backend.api.file_upload.create_error_context') as mock_context, \
             patch('backend.api.file_upload.handle_generic_error', return_value=Mock()) as mock_error_handler:
            
            from backend.api.file_upload import upload_multiple_files
            
            mock_request = Mock()
            
            result = await upload_multiple_files(
                mock_request, 
                mock_multiple_upload_files, 
                project_id, 
                mock_current_user, 
                mock_rate_limit
            )
            
            # Должен вызвать обработчик ошибок
            mock_error_handler.assert_called_once()
    
    # === GET FILE INFO TESTS ===
    
    @pytest.mark.asyncio
    async def test_get_file_info_success(self, mock_current_user, mock_file_info):
        """Тест успешного получения информации о файле"""
        file_path = "uploads/test-file.txt"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.get_file_info', return_value=mock_file_info), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import get_file_information
            
            mock_request = Mock()
            
            result = await get_file_information(mock_request, file_path, mock_current_user)
            
            assert isinstance(result, FileInfoResponse)
            assert result.success is True
            assert result.file_info.filename == mock_file_info["filename"]
            assert result.file_info.size == mock_file_info["size"]
            assert result.file_info.extension == mock_file_info["extension"]
    
    @pytest.mark.asyncio
    async def test_get_file_info_invalid_path(self, mock_current_user):
        """Тест получения информации о файле с невалидным путем"""
        file_path = "../../etc/passwd"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import get_file_information
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await get_file_information(mock_request, file_path, mock_current_user)
            
            assert exc_info.value.status_code == 400
            assert "Invalid file path" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_file_info_not_found(self, mock_current_user):
        """Тест получения информации о несуществующем файле"""
        file_path = "uploads/non-existent-file.txt"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.get_file_info', return_value=None), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import get_file_information
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await get_file_information(mock_request, file_path, mock_current_user)
            
            assert exc_info.value.status_code == 404
            assert "File not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_file_info_general_exception(self, mock_current_user):
        """Тест получения информации о файле с общим исключением"""
        file_path = "uploads/test-file.txt"
        
        with patch('backend.api.file_upload.validate_path_traversal', side_effect=Exception("Unexpected error")), \
             patch('backend.api.file_upload.create_error_context') as mock_context, \
             patch('backend.api.file_upload.handle_generic_error', return_value=Mock()) as mock_error_handler:
            
            from backend.api.file_upload import get_file_information
            
            mock_request = Mock()
            
            result = await get_file_information(mock_request, file_path, mock_current_user)
            
            # Должен вызвать обработчик ошибок
            mock_error_handler.assert_called_once()
    
    # === DELETE FILE TESTS ===
    
    @pytest.mark.asyncio
    async def test_delete_file_success(self, mock_current_user):
        """Тест успешного удаления файла"""
        file_path = "uploads/test-file.txt"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.delete_file', return_value=True), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import delete_uploaded_file
            
            mock_request = Mock()
            
            result = await delete_uploaded_file(mock_request, file_path, mock_current_user)
            
            assert result.status_code == 200
            assert result.body.decode() == '{"success":true,"message":"File deleted successfully"}'
    
    @pytest.mark.asyncio
    async def test_delete_file_invalid_path(self, mock_current_user):
        """Тест удаления файла с невалидным путем"""
        file_path = "../../etc/passwd"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import delete_uploaded_file
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_uploaded_file(mock_request, file_path, mock_current_user)
            
            assert exc_info.value.status_code == 400
            assert "Invalid file path" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_delete_file_not_found(self, mock_current_user):
        """Тест удаления несуществующего файла"""
        file_path = "uploads/non-existent-file.txt"
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.delete_file', return_value=False), \
             patch('backend.api.file_upload.create_error_context') as mock_context:
            
            # Настраиваем мок для create_error_context
            mock_context.return_value = Mock(error_id="test-error-id")
            
            from backend.api.file_upload import delete_uploaded_file
            
            mock_request = Mock()
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_uploaded_file(mock_request, file_path, mock_current_user)
            
            assert exc_info.value.status_code == 404
            assert "File not found or could not be deleted" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_delete_file_general_exception(self, mock_current_user):
        """Тест удаления файла с общим исключением"""
        file_path = "uploads/test-file.txt"
        
        with patch('backend.api.file_upload.validate_path_traversal', side_effect=Exception("Unexpected error")), \
             patch('backend.api.file_upload.create_error_context') as mock_context, \
             patch('backend.api.file_upload.handle_generic_error', return_value=Mock()) as mock_error_handler:
            
            from backend.api.file_upload import delete_uploaded_file
            
            mock_request = Mock()
            
            result = await delete_uploaded_file(mock_request, file_path, mock_current_user)
            
            # Должен вызвать обработчик ошибок
            mock_error_handler.assert_called_once()