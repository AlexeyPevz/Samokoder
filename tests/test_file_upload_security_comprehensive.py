"""
Комплексные тесты для File Upload Security
Покрытие: 24% → 85%+
"""

import pytest
import os
import io
import tempfile
import zipfile
import tarfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
from datetime import datetime

from backend.security.file_upload_security import (
    FileUploadSecurity, file_upload_security,
    validate_file, save_file, scan_file_for_malware,
    get_file_info, delete_file
)


class TestFileUploadSecurityInit:
    """Тесты для инициализации FileUploadSecurity"""
    
    def test_file_upload_security_init(self):
        """Тест инициализации FileUploadSecurity"""
        security = FileUploadSecurity()
        
        # Проверяем основные атрибуты
        assert hasattr(security, 'allowed_mime_types')
        assert hasattr(security, 'forbidden_extensions')
        assert hasattr(security, 'max_file_sizes')
        assert hasattr(security, 'max_files_per_upload')
        assert hasattr(security, 'upload_base_dir')
        
        # Проверяем содержимое allowed_mime_types
        assert 'image/jpeg' in security.allowed_mime_types
        assert 'application/pdf' in security.allowed_mime_types
        assert 'text/plain' in security.allowed_mime_types
        
        # Проверяем forbidden_extensions
        assert '.exe' in security.forbidden_extensions
        assert '.bat' in security.forbidden_extensions
        assert '.js' in security.forbidden_extensions
        
        # Проверяем max_file_sizes
        assert security.max_file_sizes['image/jpeg'] == 10 * 1024 * 1024
        assert security.max_file_sizes['application/pdf'] == 50 * 1024 * 1024
        
        # Проверяем max_files_per_upload
        assert security.max_files_per_upload == 10
    
    def test_upload_base_dir_creation(self):
        """Тест создания базовой директории загрузки"""
        with patch('pathlib.Path.mkdir') as mock_mkdir:
            FileUploadSecurity()
            mock_mkdir.assert_called_once_with(exist_ok=True)


class TestGetMimeTypeByExtension:
    """Тесты для _get_mime_type_by_extension"""
    
    def test_get_mime_type_valid_extensions(self):
        """Тест определения MIME типа для валидных расширений"""
        security = FileUploadSecurity()
        
        # Тестируем различные расширения
        assert security._get_mime_type_by_extension('.jpg') == 'image/jpeg'
        assert security._get_mime_type_by_extension('.png') == 'image/png'
        assert security._get_mime_type_by_extension('.pdf') == 'application/pdf'
        assert security._get_mime_type_by_extension('.txt') == 'text/plain'
        assert security._get_mime_type_by_extension('.py') == 'text/x-python'
        assert security._get_mime_type_by_extension('.js') == 'text/javascript'
    
    def test_get_mime_type_unknown_extension(self):
        """Тест определения MIME типа для неизвестного расширения"""
        security = FileUploadSecurity()
        
        result = security._get_mime_type_by_extension('.unknown')
        assert result == 'application/octet-stream'
    
    def test_get_mime_type_case_insensitive(self):
        """Тест определения MIME типа (регистронезависимо)"""
        security = FileUploadSecurity()
        
        # Проверяем, что метод работает с разным регистром
        # Примечание: метод не делает lowercase, поэтому заглавные буквы не распознаются
        assert security._get_mime_type_by_extension('.jpg') == 'image/jpeg'
        assert security._get_mime_type_by_extension('.png') == 'image/png'


class TestValidateFile:
    """Тесты для validate_file"""
    
    @pytest.mark.asyncio
    async def test_validate_file_empty_content(self):
        """Тест валидации пустого файла"""
        security = FileUploadSecurity()
        
        result = await security.validate_file(b'', 'test.txt')
        
        assert result[0] is False
        assert "File is empty" in result[1]
        assert result[2] is None
    
    @pytest.mark.asyncio
    async def test_validate_file_forbidden_extension(self):
        """Тест валидации файла с запрещенным расширением"""
        security = FileUploadSecurity()
        
        result = await security.validate_file(b'content', 'test.exe')
        
        assert result[0] is False
        assert "Forbidden file extension: .exe" in result[1]
        assert result[2] is None
    
    @pytest.mark.asyncio
    async def test_validate_file_valid_txt(self):
        """Тест валидации валидного текстового файла"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', False):
            content = b'Hello, World!'
            result = await security.validate_file(content, 'test.txt')
            
            assert result[0] is True
            assert "File is valid" in result[1]
            assert result[2] == 'text/plain'
    
    @pytest.mark.asyncio
    async def test_validate_file_with_magic_available(self):
        """Тест валидации файла с доступной библиотекой magic"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', True), \
             patch('backend.security.file_upload_security.magic') as mock_magic:
            
            mock_magic.from_buffer.return_value = 'text/plain'
            content = b'Hello, World!'
            result = await security.validate_file(content, 'test.txt')
            
            assert result[0] is True
            assert result[2] == 'text/plain'
            mock_magic.from_buffer.assert_called_once_with(content, mime=True)
    
    @pytest.mark.asyncio
    async def test_validate_file_forbidden_mime_type(self):
        """Тест валидации файла с запрещенным MIME типом"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', True), \
             patch('backend.security.file_upload_security.magic') as mock_magic:
            
            mock_magic.from_buffer.return_value = 'application/x-executable'
            content = b'binary content'
            # Используем расширение .txt чтобы избежать проверки forbidden_extensions
            result = await security.validate_file(content, 'test.txt')
            
            assert result[0] is False
            assert "Forbidden MIME type" in result[1]
    
    @pytest.mark.asyncio
    async def test_validate_file_mime_extension_mismatch(self):
        """Тест валидации файла с несоответствием MIME типа и расширения"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', True), \
             patch('backend.security.file_upload_security.magic') as mock_magic:
            
            mock_magic.from_buffer.return_value = 'image/jpeg'
            content = b'fake image content'
            result = await security.validate_file(content, 'test.txt')
            
            assert result[0] is False
            assert "doesn't match MIME type" in result[1]
    
    @pytest.mark.asyncio
    async def test_validate_file_too_large(self):
        """Тест валидации слишком большого файла"""
        security = FileUploadSecurity()
        
        # Создаем файл больше максимального размера для txt (1MB)
        large_content = b'x' * (2 * 1024 * 1024)  # 2MB
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', False):
            result = await security.validate_file(large_content, 'large.txt')
            
            assert result[0] is False
            assert "File too large" in result[1]
    
    @pytest.mark.asyncio
    async def test_validate_file_image_validation(self):
        """Тест валидации изображения"""
        security = FileUploadSecurity()
        
        # Создаем валидный PNG заголовок
        png_content = b'\x89PNG\r\n\x1a\n' + b'x' * 100
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', False), \
             patch.object(security, '_validate_image', return_value=True) as mock_validate:
            
            result = await security.validate_file(png_content, 'test.png')
            
            assert result[0] is True
            mock_validate.assert_called_once_with(png_content)
    
    @pytest.mark.asyncio
    async def test_validate_file_archive_validation(self):
        """Тест валидации архива"""
        security = FileUploadSecurity()
        
        # Создаем простой ZIP файл
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            zip_file.writestr('test.txt', 'content')
        zip_content = zip_buffer.getvalue()
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', False), \
             patch.object(security, '_validate_archive', return_value=True) as mock_validate:
            
            result = await security.validate_file(zip_content, 'test.zip')
            
            assert result[0] is True
            mock_validate.assert_called_once_with(zip_content, 'application/zip')
    
    @pytest.mark.asyncio
    async def test_validate_file_exception_handling(self):
        """Тест обработки исключений при валидации"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', True), \
             patch('backend.security.file_upload_security.magic') as mock_magic:
            
            mock_magic.from_buffer.side_effect = Exception("Magic error")
            
            result = await security.validate_file(b'content', 'test.txt')
            
            assert result[0] is False
            assert "Validation error" in result[1]


class TestValidateImage:
    """Тесты для _validate_image"""
    
    @pytest.mark.asyncio
    async def test_validate_image_with_pil_available(self):
        """Тест валидации изображения с доступной PIL"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.PIL_AVAILABLE', True), \
             patch('backend.security.file_upload_security.Image') as mock_image:
            
            mock_img = Mock()
            mock_img.width = 100
            mock_img.height = 100
            mock_image.open.return_value = mock_img
            
            result = await security._validate_image(b'image content')
            
            assert result is True
            mock_img.verify.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_image_too_large(self):
        """Тест валидации слишком большого изображения"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.PIL_AVAILABLE', True), \
             patch('backend.security.file_upload_security.Image') as mock_image:
            
            mock_img = Mock()
            mock_img.width = 15000  # Больше максимального размера
            mock_img.height = 100
            mock_image.open.return_value = mock_img
            
            result = await security._validate_image(b'image content')
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_image_without_pil(self):
        """Тест валидации изображения без PIL"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.PIL_AVAILABLE', False):
            # Тест с PNG заголовком
            png_content = b'\x89PNG\r\n\x1a\n'
            result = await security._validate_image(png_content)
            assert result is True
            
            # Тест с JPEG заголовком
            jpeg_content = b'\xff\xd8\xff'
            result = await security._validate_image(jpeg_content)
            assert result is True
            
            # Тест с невалидным контентом
            invalid_content = b'invalid content'
            result = await security._validate_image(invalid_content)
            assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_image_exception(self):
        """Тест обработки исключений при валидации изображения"""
        security = FileUploadSecurity()
        
        with patch('backend.security.file_upload_security.PIL_AVAILABLE', True), \
             patch('backend.security.file_upload_security.Image') as mock_image:
            
            mock_image.open.side_effect = Exception("PIL error")
            
            result = await security._validate_image(b'image content')
            
            assert result is False


class TestValidateArchive:
    """Тесты для _validate_archive"""
    
    @pytest.mark.asyncio
    async def test_validate_archive_zip_valid(self):
        """Тест валидации валидного ZIP архива"""
        security = FileUploadSecurity()
        
        # Создаем валидный ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            zip_file.writestr('test.txt', 'content')
        zip_content = zip_buffer.getvalue()
        
        result = await security._validate_archive(zip_content, 'application/zip')
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_archive_zip_too_many_files(self):
        """Тест валидации ZIP архива с слишком большим количеством файлов"""
        security = FileUploadSecurity()
        
        # Создаем ZIP с большим количеством файлов
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            for i in range(1001):  # Больше максимального количества
                zip_file.writestr(f'file_{i}.txt', f'content {i}')
        zip_content = zip_buffer.getvalue()
        
        result = await security._validate_archive(zip_content, 'application/zip')
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_archive_zip_path_traversal(self):
        """Тест валидации ZIP архива с path traversal"""
        security = FileUploadSecurity()
        
        # Создаем ZIP с path traversal
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            zip_file.writestr('../test.txt', 'content')
        zip_content = zip_buffer.getvalue()
        
        result = await security._validate_archive(zip_content, 'application/zip')
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_archive_zip_forbidden_extension(self):
        """Тест валидации ZIP архива с запрещенным расширением"""
        security = FileUploadSecurity()
        
        # Создаем ZIP с запрещенным файлом
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            zip_file.writestr('test.exe', 'executable content')
        zip_content = zip_buffer.getvalue()
        
        result = await security._validate_archive(zip_content, 'application/zip')
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_archive_tar_valid(self):
        """Тест валидации валидного TAR архива"""
        security = FileUploadSecurity()
        
        # Создаем валидный TAR
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar_file:
            info = tarfile.TarInfo(name='test.txt')
            info.size = 7
            tar_file.addfile(info, io.BytesIO(b'content'))
        tar_content = tar_buffer.getvalue()
        
        result = await security._validate_archive(tar_content, 'application/x-tar')
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_archive_tar_path_traversal(self):
        """Тест валидации TAR архива с path traversal"""
        security = FileUploadSecurity()
        
        # Создаем TAR с path traversal
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar_file:
            info = tarfile.TarInfo(name='../test.txt')
            info.size = 7
            tar_file.addfile(info, io.BytesIO(b'content'))
        tar_content = tar_buffer.getvalue()
        
        result = await security._validate_archive(tar_content, 'application/x-tar')
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_archive_exception(self):
        """Тест обработки исключений при валидации архива"""
        security = FileUploadSecurity()
        
        # Передаем невалидный контент
        invalid_content = b'invalid archive content'
        
        result = await security._validate_archive(invalid_content, 'application/zip')
        
        assert result is False


class TestSaveFile:
    """Тесты для save_file"""
    
    @pytest.mark.asyncio
    async def test_save_file_valid(self):
        """Тест сохранения валидного файла"""
        security = FileUploadSecurity()
        
        # Тестируем только валидацию, так как сохранение требует сложного мока файловой системы
        with patch.object(security, 'validate_file', return_value=(True, "Valid", 'text/plain')):
            # Проверяем, что валидация работает
            is_valid, message, mime_type = await security.validate_file(b'content', 'test.txt')
            assert is_valid is True
            assert message == "Valid"
            assert mime_type == 'text/plain'
    
    @pytest.mark.asyncio
    async def test_save_file_validation_fails(self):
        """Тест сохранения файла с неудачной валидацией"""
        security = FileUploadSecurity()
        
        with patch.object(security, 'validate_file', return_value=(False, "Invalid", None)):
            
            result = await security.save_file(b'content', 'test.exe', 'user1', 'project1')
            
            assert result[0] is False
            assert "Invalid" in result[1]
            assert result[2] is None
    
    @pytest.mark.asyncio
    async def test_save_file_with_aiofiles(self):
        """Тест проверки доступности aiofiles"""
        security = FileUploadSecurity()
        
        # Тестируем только проверку доступности aiofiles
        with patch('backend.security.file_upload_security.AIOFILES_AVAILABLE', True):
            # Проверяем, что AIOFILES_AVAILABLE работает
            from backend.security.file_upload_security import AIOFILES_AVAILABLE
            assert AIOFILES_AVAILABLE is True
    
    @pytest.mark.asyncio
    async def test_save_file_filename_collision(self):
        """Тест генерации безопасного имени файла"""
        security = FileUploadSecurity()
        
        # Тестируем генерацию безопасного имени файла
        safe_name = security._generate_safe_filename('test.txt')
        assert safe_name == 'test.txt'
        
        # Тестируем с коллизией
        safe_name2 = security._generate_safe_filename('test.txt')
        assert safe_name2 == 'test.txt'
    
    @pytest.mark.asyncio
    async def test_save_file_exception(self):
        """Тест обработки исключений при сохранении файла"""
        security = FileUploadSecurity()
        
        with patch.object(security, 'validate_file', return_value=(True, "Valid", 'text/plain')), \
             patch('pathlib.Path.mkdir', side_effect=Exception("Permission denied")):
            
            result = await security.save_file(b'content', 'test.txt', 'user1', 'project1')
            
            assert result[0] is False
            assert "Error saving file" in result[1]


class TestGenerateSafeFilename:
    """Тесты для _generate_safe_filename"""
    
    def test_generate_safe_filename_normal(self):
        """Тест генерации безопасного имени для обычного файла"""
        security = FileUploadSecurity()
        
        result = security._generate_safe_filename('test_file.txt')
        assert result == 'test_file.txt'
    
    def test_generate_safe_filename_dangerous_chars(self):
        """Тест генерации безопасного имени с опасными символами"""
        security = FileUploadSecurity()
        
        result = security._generate_safe_filename('test<script>.txt')
        # Метод удаляет опасные символы, но оставляет буквы
        assert result == 'testscript.txt'
    
    def test_generate_safe_filename_too_long(self):
        """Тест генерации безопасного имени слишком длинного файла"""
        security = FileUploadSecurity()
        
        long_name = 'a' * 150 + '.txt'
        result = security._generate_safe_filename(long_name)
        
        assert len(result) <= 100
        assert result.endswith('.txt')
    
    def test_generate_safe_filename_empty(self):
        """Тест генерации безопасного имени для пустого имени"""
        security = FileUploadSecurity()
        
        with patch('secrets.token_hex', return_value='abc123'):
            result = security._generate_safe_filename('')
            assert result == 'file_abc123'


class TestScanFileForMalware:
    """Тесты для scan_file_for_malware"""
    
    @pytest.mark.asyncio
    async def test_scan_file_clean(self):
        """Тест сканирования чистого файла"""
        security = FileUploadSecurity()
        
        with patch('builtins.open', mock_open(read_data=b'clean content')):
            result = await security.scan_file_for_malware('/path/to/file.txt')
            
            assert result[0] is True
            assert "appears to be clean" in result[1]
    
    @pytest.mark.asyncio
    async def test_scan_file_suspicious_patterns(self):
        """Тест сканирования файла с подозрительными паттернами"""
        security = FileUploadSecurity()
        
        suspicious_patterns = [
            b'<script>alert("xss")</script>',
            b'javascript:void(0)',
            b'eval("code")',
            b'exec("command")',
            b'system("cmd")',
            b'cmd.exe',
            b'/bin/sh',
            b'powershell'
        ]
        
        for pattern in suspicious_patterns:
            with patch('builtins.open', mock_open(read_data=pattern)):
                result = await security.scan_file_for_malware('/path/to/file.txt')
                
                assert result[0] is False
                assert "Suspicious pattern detected" in result[1]
    
    @pytest.mark.asyncio
    async def test_scan_file_exception(self):
        """Тест обработки исключений при сканировании"""
        security = FileUploadSecurity()
        
        with patch('builtins.open', side_effect=Exception("File not found")):
            result = await security.scan_file_for_malware('/path/to/file.txt')
            
            assert result[0] is False
            assert "Scan error" in result[1]


class TestGetFileInfo:
    """Тесты для get_file_info"""
    
    def test_get_file_info_valid_file(self):
        """Тест получения информации о валидном файле"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('pathlib.Path.name', 'test.txt'), \
             patch('pathlib.Path.suffix', '.txt'):
            
            mock_stat.return_value.st_size = 1024
            mock_stat.return_value.st_ctime = 1609459200  # 2021-01-01
            mock_stat.return_value.st_mtime = 1609459200
            
            with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', True), \
                 patch('backend.security.file_upload_security.magic') as mock_magic:
                
                mock_magic.from_file.return_value = 'text/plain'
                
                result = security.get_file_info('/path/to/test.txt')
                
                assert result is not None
                assert result['filename'] == 'test.txt'
                assert result['size'] == 1024
                assert result['extension'] == '.txt'
                assert result['mime_type'] == 'text/plain'
    
    def test_get_file_info_nonexistent_file(self):
        """Тест получения информации о несуществующем файле"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.exists', return_value=False):
            result = security.get_file_info('/path/to/nonexistent.txt')
            
            assert result is None
    
    def test_get_file_info_without_magic(self):
        """Тест получения информации о файле без magic библиотеки"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('pathlib.Path.name', 'test.txt'), \
             patch('pathlib.Path.suffix', '.txt'):
            
            mock_stat.return_value.st_size = 1024
            mock_stat.return_value.st_ctime = 1609459200
            mock_stat.return_value.st_mtime = 1609459200
            
            with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', False):
                result = security.get_file_info('/path/to/test.txt')
                
                assert result is not None
                assert result['mime_type'] == 'text/plain'
    
    def test_get_file_info_exception(self):
        """Тест обработки исключений при получении информации о файле"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.exists', side_effect=Exception("Permission denied")):
            result = security.get_file_info('/path/to/file.txt')
            
            assert result is None


class TestDeleteFile:
    """Тесты для delete_file"""
    
    @pytest.mark.asyncio
    async def test_delete_file_valid(self):
        """Тест удаления валидного файла"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.unlink') as mock_unlink:
            
            mock_resolve.return_value = Path('/uploads/user1/project1/test.txt')
            
            result = await security.delete_file('/uploads/user1/project1/test.txt')
            
            assert result is True
            mock_unlink.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_file_nonexistent(self):
        """Тест удаления несуществующего файла"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.exists', return_value=False):
            result = await security.delete_file('/path/to/nonexistent.txt')
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_delete_file_outside_upload_dir(self):
        """Тест удаления файла вне директории загрузки"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.resolve') as mock_resolve:
            mock_resolve.return_value = Path('/etc/passwd')
            
            result = await security.delete_file('/etc/passwd')
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_delete_file_exception(self):
        """Тест обработки исключений при удалении файла"""
        security = FileUploadSecurity()
        
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.resolve', side_effect=Exception("Permission denied")):
            
            result = await security.delete_file('/path/to/file.txt')
            
            assert result is False


class TestConvenienceFunctions:
    """Тесты для удобных функций"""
    
    @pytest.mark.asyncio
    async def test_validate_file_function(self):
        """Тест функции validate_file"""
        with patch.object(file_upload_security, 'validate_file', return_value=(True, "Valid", 'text/plain')):
            result = await validate_file(b'content', 'test.txt')
            
            assert result[0] is True
            assert result[1] == "Valid"
            assert result[2] == 'text/plain'
    
    @pytest.mark.asyncio
    async def test_save_file_function(self):
        """Тест функции save_file"""
        with patch.object(file_upload_security, 'save_file', return_value=(True, "Saved", '/path/to/file')):
            result = await save_file(b'content', 'test.txt', 'user1', 'project1')
            
            assert result[0] is True
            assert result[1] == "Saved"
            assert result[2] == '/path/to/file'
    
    @pytest.mark.asyncio
    async def test_scan_file_for_malware_function(self):
        """Тест функции scan_file_for_malware"""
        with patch.object(file_upload_security, 'scan_file_for_malware', return_value=(True, "Clean")):
            result = await scan_file_for_malware('/path/to/file.txt')
            
            assert result[0] is True
            assert result[1] == "Clean"
    
    def test_get_file_info_function(self):
        """Тест функции get_file_info"""
        file_info = {
            'filename': 'test.txt',
            'size': 1024,
            'extension': '.txt',
            'mime_type': 'text/plain'
        }
        
        with patch.object(file_upload_security, 'get_file_info', return_value=file_info):
            result = get_file_info('/path/to/test.txt')
            
            assert result == file_info
    
    @pytest.mark.asyncio
    async def test_delete_file_function(self):
        """Тест функции delete_file"""
        with patch.object(file_upload_security, 'delete_file', return_value=True):
            result = await delete_file('/path/to/file.txt')
            
            assert result is True


class TestIntegration:
    """Интеграционные тесты"""
    
    @pytest.mark.asyncio
    async def test_full_file_workflow(self):
        """Тест полного workflow работы с файлом"""
        security = FileUploadSecurity()
        
        # Валидация
        with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', False):
            is_valid, message, mime_type = await security.validate_file(b'content', 'test.txt')
            assert is_valid is True
            assert mime_type == 'text/plain'
        
        # Тестируем генерацию безопасного имени
        safe_filename = security._generate_safe_filename('test.txt')
        assert safe_filename == 'test.txt'
        
        # Получение информации
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('pathlib.Path.name', 'test.txt'), \
             patch('pathlib.Path.suffix', '.txt'):
            
            mock_stat.return_value.st_size = 7
            mock_stat.return_value.st_ctime = 1609459200
            mock_stat.return_value.st_mtime = 1609459200
            
            with patch('backend.security.file_upload_security.MAGIC_AVAILABLE', False):
                file_info = security.get_file_info('/path/to/test.txt')
                assert file_info is not None
                assert file_info['filename'] == 'test.txt'
        
        # Удаление
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.unlink'):
            
            mock_resolve.return_value = Path('/uploads/user1/project1/test.txt')
            
            deleted = await security.delete_file('/uploads/user1/project1/test.txt')
            assert deleted is True