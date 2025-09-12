"""
Comprehensive tests for File Upload API endpoints
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, status, UploadFile
from fastapi.testclient import TestClient
from backend.api.file_upload import router
from backend.models.responses import FileUploadResponse, FileInfoResponse
from backend.auth.dependencies import get_current_user
from backend.middleware.secure_rate_limiter import file_upload_rate_limit
from backend.security.secure_error_handler import ErrorSeverity
import io


class TestFileUploadAPIUpload:
    """Test single file upload endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        """Mock current user"""
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        """Mock rate limit"""
        return {"requests": 1, "limit": 100}
    
    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI request"""
        request = Mock()
        request.method = "POST"
        request.url = "http://test.com/upload"
        request.headers = {"content-type": "multipart/form-data"}
        return request
    
    @pytest.fixture
    def mock_upload_file(self):
        """Mock uploaded file"""
        file = Mock(spec=UploadFile)
        file.filename = "test.txt"
        file.content_type = "text/plain"
        file.read = AsyncMock(return_value=b"Hello, World!")
        file.size = 13
        return file
    
    @pytest.mark.asyncio
    async def test_upload_file_success(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_file):
        """Test successful file upload"""
        from backend.api.file_upload import upload_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(True, "Saved", "/uploads/test.txt")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(True, "Clean")), \
             patch('backend.api.file_upload.get_file_info', return_value={"size": 13, "created": "2024-01-01"}):
            
            result = await upload_file(
                mock_request,
                mock_upload_file,
                "project123",
                mock_current_user,
                mock_rate_limit
            )
            
            assert isinstance(result, FileUploadResponse)
            assert result.success is True
            assert result.message == "File uploaded successfully"
            assert result.file_path == "/uploads/test.txt"
            assert result.filename == "test.txt"
            assert result.mime_type == "text/plain"
            assert result.size == 13
            assert result.file_info == {"size": 13, "created": "2024-01-01"}
    
    @pytest.mark.asyncio
    async def test_upload_file_invalid_project_id(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_file):
        """Test file upload with invalid project ID"""
        from backend.api.file_upload import upload_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request,
                    mock_upload_file,
                    "../invalid/project",
                    mock_current_user,
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid project ID" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_validation_failed(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_file):
        """Test file upload with validation failure"""
        from backend.api.file_upload import upload_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(False, "File too large", "application/octet-stream")):
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request,
                    mock_upload_file,
                    "project123",
                    mock_current_user,
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "File too large" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_save_failed(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_file):
        """Test file upload with save failure"""
        from backend.api.file_upload import upload_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(False, "Disk full", None)):
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request,
                    mock_upload_file,
                    "project123",
                    mock_current_user,
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Disk full" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_malware_detected(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_file):
        """Test file upload with malware detection"""
        from backend.api.file_upload import upload_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(True, "Saved", "/uploads/test.txt")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(False, "Malware detected")), \
             patch('backend.api.file_upload.delete_file', return_value=True):
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(
                    mock_request,
                    mock_upload_file,
                    "project123",
                    mock_current_user,
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "File rejected: Malware detected" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_generic_error(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_file):
        """Test file upload with generic error"""
        from backend.api.file_upload import upload_file
        
        with patch('backend.api.file_upload.validate_path_traversal', side_effect=Exception("Unexpected error")):
            result = await upload_file(
                mock_request,
                mock_upload_file,
                "project123",
                mock_current_user,
                mock_rate_limit
            )
            
            # Should return error response from handle_generic_error
            assert hasattr(result, 'status_code') or isinstance(result, dict)


class TestFileUploadAPIMultiple:
    """Test multiple file upload endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.fixture
    def mock_request(self):
        request = Mock()
        request.method = "POST"
        request.url = "http://test.com/upload-multiple"
        request.headers = {"content-type": "multipart/form-data"}
        return request
    
    @pytest.fixture
    def mock_upload_files(self):
        """Mock multiple uploaded files"""
        files = []
        for i in range(3):
            file = Mock(spec=UploadFile)
            file.filename = f"test{i}.txt"
            file.content_type = "text/plain"
            file.read = AsyncMock(return_value=f"Hello, World {i}!".encode())
            file.size = 15
            files.append(file)
        return files
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_success(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_files):
        """Test successful multiple file upload"""
        from backend.api.file_upload import upload_multiple_files
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(True, "Saved", "/uploads/test.txt")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(True, "Clean")), \
             patch('backend.api.file_upload.get_file_info', return_value={"size": 15, "created": "2024-01-01"}):
            
            result = await upload_multiple_files(
                mock_request,
                mock_upload_files,
                "project123",
                mock_current_user,
                mock_rate_limit
            )
            
            assert isinstance(result, list)
            assert len(result) == 3
            for i, response in enumerate(result):
                assert isinstance(response, FileUploadResponse)
                assert response.success is True
                assert response.filename == f"test{i}.txt"
                assert response.message == "File uploaded successfully"
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_too_many(self, mock_current_user, mock_rate_limit, mock_request):
        """Test multiple file upload with too many files"""
        from backend.api.file_upload import upload_multiple_files
        
        # Create 11 files (more than limit of 10)
        files = []
        for i in range(11):
            file = Mock(spec=UploadFile)
            file.filename = f"test{i}.txt"
            files.append(file)
        
        with pytest.raises(HTTPException) as exc_info:
            await upload_multiple_files(
                mock_request,
                files,
                "project123",
                mock_current_user,
                mock_rate_limit
            )
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "Too many files" in str(exc_info.value.detail)
        assert "Maximum 10 files" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_invalid_project_id(self, mock_current_user, mock_rate_limit, mock_request, mock_upload_files):
        """Test multiple file upload with invalid project ID"""
        from backend.api.file_upload import upload_multiple_files
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await upload_multiple_files(
                    mock_request,
                    mock_upload_files,
                    "../invalid/project",
                    mock_current_user,
                    mock_rate_limit
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid project ID" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_mixed_results(self, mock_current_user, mock_rate_limit, mock_request):
        """Test multiple file upload with mixed success/failure results"""
        from backend.api.file_upload import upload_multiple_files
        
        files = []
        for i in range(3):
            file = Mock(spec=UploadFile)
            file.filename = f"test{i}.txt"
            file.read = AsyncMock(return_value=f"Hello, World {i}!".encode())
            files.append(file)
        
        def mock_validate_file(content, filename):
            # First file fails validation, others pass
            if "test0.txt" in filename:
                return (False, "File too large", "application/octet-stream")
            return (True, "Valid file", "text/plain")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', side_effect=mock_validate_file), \
             patch('backend.api.file_upload.save_file', return_value=(True, "Saved", "/uploads/test.txt")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(True, "Clean")), \
             patch('backend.api.file_upload.get_file_info', return_value={"size": 15, "created": "2024-01-01"}):
            
            result = await upload_multiple_files(
                mock_request,
                files,
                "project123",
                mock_current_user,
                mock_rate_limit
            )
            
            assert isinstance(result, list)
            assert len(result) == 3
            
            # First file should fail
            assert result[0].success is False
            assert "Validation failed: File too large" in result[0].message
            
            # Other files should succeed
            assert result[1].success is True
            assert result[2].success is True
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_save_failure(self, mock_current_user, mock_rate_limit, mock_request):
        """Test multiple file upload with save failure"""
        from backend.api.file_upload import upload_multiple_files
        
        file = Mock(spec=UploadFile)
        file.filename = "test.txt"
        file.read = AsyncMock(return_value=b"Hello, World!")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(False, "Disk full", None)):
            
            result = await upload_multiple_files(
                mock_request,
                [file],
                "project123",
                mock_current_user,
                mock_rate_limit
            )
            
            assert isinstance(result, list)
            assert len(result) == 1
            assert result[0].success is False
            assert "Save failed: Disk full" in result[0].message
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_malware_detection(self, mock_current_user, mock_rate_limit, mock_request):
        """Test multiple file upload with malware detection"""
        from backend.api.file_upload import upload_multiple_files
        
        file = Mock(spec=UploadFile)
        file.filename = "test.txt"
        file.read = AsyncMock(return_value=b"Hello, World!")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(True, "Valid file", "text/plain")), \
             patch('backend.api.file_upload.save_file', return_value=(True, "Saved", "/uploads/test.txt")), \
             patch('backend.api.file_upload.scan_file_for_malware', return_value=(False, "Malware detected")), \
             patch('backend.api.file_upload.delete_file', return_value=True):
            
            result = await upload_multiple_files(
                mock_request,
                [file],
                "project123",
                mock_current_user,
                mock_rate_limit
            )
            
            assert isinstance(result, list)
            assert len(result) == 1
            assert result[0].success is False
            assert "File rejected: Malware detected" in result[0].message


class TestFileUploadAPIFileInfo:
    """Test file information endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_request(self):
        request = Mock()
        request.method = "GET"
        request.url = "http://test.com/info/test.txt"
        request.headers = {}
        return request
    
    @pytest.mark.asyncio
    async def test_get_file_info_success(self, mock_current_user, mock_request):
        """Test successful file info retrieval"""
        from backend.api.file_upload import get_file_information
        
        mock_file_info = {
            "filename": "test.txt",
            "size": 1024,
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "mime_type": "text/plain"
        }
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.get_file_info', return_value=mock_file_info):
            
            result = await get_file_information(mock_request, "uploads/test.txt", mock_current_user)
            
            assert isinstance(result, FileInfoResponse)
            assert result.success is True
            assert result.file_info == mock_file_info
    
    @pytest.mark.asyncio
    async def test_get_file_info_invalid_path(self, mock_current_user, mock_request):
        """Test file info with invalid path"""
        from backend.api.file_upload import get_file_information
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await get_file_information(mock_request, "../../../etc/passwd", mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid file path" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_file_info_not_found(self, mock_current_user, mock_request):
        """Test file info when file not found"""
        from backend.api.file_upload import get_file_information
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.get_file_info', return_value=None):
            
            with pytest.raises(HTTPException) as exc_info:
                await get_file_information(mock_request, "uploads/nonexistent.txt", mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "File not found" in str(exc_info.value.detail)


class TestFileUploadAPIDelete:
    """Test file deletion endpoint"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_request(self):
        request = Mock()
        request.method = "DELETE"
        request.url = "http://test.com/delete/test.txt"
        request.headers = {}
        return request
    
    @pytest.mark.asyncio
    async def test_delete_file_success(self, mock_current_user, mock_request):
        """Test successful file deletion"""
        from backend.api.file_upload import delete_uploaded_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.delete_file', return_value=True):
            
            result = await delete_uploaded_file(mock_request, "uploads/test.txt", mock_current_user)
            
            assert result.status_code == 200
            assert result.body == b'{"success":true,"message":"File deleted successfully"}'
    
    @pytest.mark.asyncio
    async def test_delete_file_invalid_path(self, mock_current_user, mock_request):
        """Test file deletion with invalid path"""
        from backend.api.file_upload import delete_uploaded_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await delete_uploaded_file(mock_request, "../../../etc/passwd", mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid file path" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_delete_file_not_found(self, mock_current_user, mock_request):
        """Test file deletion when file not found"""
        from backend.api.file_upload import delete_uploaded_file
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.delete_file', return_value=False):
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_uploaded_file(mock_request, "uploads/nonexistent.txt", mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "File not found or could not be deleted" in str(exc_info.value.detail)


class TestFileUploadAPIEdgeCases:
    """Test edge cases and error scenarios"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": "user123", "email": "test@example.com"}
    
    @pytest.fixture
    def mock_rate_limit(self):
        return {"requests": 1, "limit": 100}
    
    @pytest.fixture
    def mock_request(self):
        request = Mock()
        request.method = "POST"
        request.url = "http://test.com/upload"
        request.headers = {"content-type": "multipart/form-data"}
        return request
    
    @pytest.mark.asyncio
    async def test_upload_file_no_project_id(self, mock_current_user, mock_rate_limit, mock_request):
        """Test file upload without project ID"""
        from backend.api.file_upload import upload_file
        
        file = Mock(spec=UploadFile)
        file.filename = "test.txt"
        file.read = AsyncMock(return_value=b"Hello, World!")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(mock_request, file, None, mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid project ID" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_empty_filename(self, mock_current_user, mock_rate_limit, mock_request):
        """Test file upload with empty filename"""
        from backend.api.file_upload import upload_file
        
        file = Mock(spec=UploadFile)
        file.filename = ""
        file.read = AsyncMock(return_value=b"Hello, World!")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(False, "Empty filename", "application/octet-stream")):
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(mock_request, file, "project123", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Empty filename" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_empty_content(self, mock_current_user, mock_rate_limit, mock_request):
        """Test file upload with empty content"""
        from backend.api.file_upload import upload_file
        
        file = Mock(spec=UploadFile)
        file.filename = "empty.txt"
        file.read = AsyncMock(return_value=b"")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(False, "Empty file", "application/octet-stream")):
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(mock_request, file, "project123", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Empty file" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_multiple_files_empty_list(self, mock_current_user, mock_rate_limit, mock_request):
        """Test multiple file upload with empty file list"""
        from backend.api.file_upload import upload_multiple_files
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True):
            result = await upload_multiple_files(
                mock_request,
                [],
                "project123",
                mock_current_user,
                mock_rate_limit
            )
            
            assert isinstance(result, list)
            assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_upload_file_large_size(self, mock_current_user, mock_rate_limit, mock_request):
        """Test file upload with large file size"""
        from backend.api.file_upload import upload_file
        
        # Simulate large file content
        large_content = b"x" * (10 * 1024 * 1024)  # 10MB
        
        file = Mock(spec=UploadFile)
        file.filename = "large.txt"
        file.read = AsyncMock(return_value=large_content)
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(False, "File too large", "application/octet-stream")):
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(mock_request, file, "project123", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "File too large" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_suspicious_extension(self, mock_current_user, mock_rate_limit, mock_request):
        """Test file upload with suspicious file extension"""
        from backend.api.file_upload import upload_file
        
        file = Mock(spec=UploadFile)
        file.filename = "malicious.exe"
        file.read = AsyncMock(return_value=b"executable content")
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.validate_file', return_value=(False, "Executable files not allowed", "application/octet-stream")):
            
            with pytest.raises(HTTPException) as exc_info:
                await upload_file(mock_request, file, "project123", mock_current_user, mock_rate_limit)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Executable files not allowed" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_upload_file_network_error(self, mock_current_user, mock_rate_limit, mock_request):
        """Test file upload with network error during save"""
        from backend.api.file_upload import upload_file
        
        file = Mock(spec=UploadFile)
        file.filename = "test.txt"
        file.read = AsyncMock(side_effect=Exception("Network error"))
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True):
            result = await upload_file(mock_request, file, "project123", mock_current_user, mock_rate_limit)
            
            # Should return error response from handle_generic_error
            assert hasattr(result, 'status_code') or isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_get_file_info_path_traversal_attempt(self, mock_current_user):
        """Test file info with path traversal attempt"""
        from backend.api.file_upload import get_file_information
        
        request = Mock()
        request.method = "GET"
        request.url = "http://test.com/info/../../../etc/passwd"
        request.headers = {}
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await get_file_information(request, "../../../etc/passwd", mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid file path" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_delete_file_permission_error(self, mock_current_user):
        """Test file deletion with permission error"""
        from backend.api.file_upload import delete_uploaded_file
        
        request = Mock()
        request.method = "DELETE"
        request.url = "http://test.com/delete/protected.txt"
        request.headers = {}
        
        with patch('backend.api.file_upload.validate_path_traversal', return_value=True), \
             patch('backend.api.file_upload.delete_file', side_effect=PermissionError("Permission denied")):
            
            result = await delete_uploaded_file(request, "uploads/protected.txt", mock_current_user)
            
            # Should return error response from handle_generic_error
            assert hasattr(result, 'status_code') or isinstance(result, dict)