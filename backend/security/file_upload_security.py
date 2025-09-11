"""
Безопасная загрузка файлов
Защита от malware, path traversal и других атак
"""

import os
import hashlib
import logging
import io
import secrets
from typing import Dict, List, Optional, Tuple, BinaryIO
from pathlib import Path
from datetime import datetime
import zipfile
import tarfile

# Опциональные импорты с fallback
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    magic = None

try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False
    aiofiles = None

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None

logger = logging.getLogger(__name__)

class FileUploadSecurity:
    """Безопасная загрузка файлов"""
    
    def __init__(self):
        # Разрешенные MIME типы
        self.allowed_mime_types = {
            # Изображения
            'image/jpeg': ['.jpg', '.jpeg'],
            'image/png': ['.png'],
            'image/gif': ['.gif'],
            'image/webp': ['.webp'],
            'image/svg+xml': ['.svg'],
            
            # Документы
            'application/pdf': ['.pdf'],
            'text/plain': ['.txt'],
            'text/csv': ['.csv'],
            'application/json': ['.json'],
            'application/xml': ['.xml'],
            
            # Архивы
            'application/zip': ['.zip'],
            'application/x-tar': ['.tar'],
            'application/gzip': ['.gz'],
            
            # Код
            'text/x-python': ['.py'],
            'text/javascript': ['.js'],
            'text/css': ['.css'],
            'text/html': ['.html', '.htm'],
        }
        
        # Запрещенные расширения
        self.forbidden_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            '.jar', '.php', '.asp', '.aspx', '.jsp', '.sh', '.ps1', '.psm1'
        }
        
        # Максимальные размеры файлов (в байтах)
        self.max_file_sizes = {
            'image/jpeg': 10 * 1024 * 1024,  # 10 MB
            'image/png': 10 * 1024 * 1024,   # 10 MB
            'image/gif': 5 * 1024 * 1024,    # 5 MB
            'image/webp': 10 * 1024 * 1024,  # 10 MB
            'image/svg+xml': 1 * 1024 * 1024, # 1 MB
            'application/pdf': 50 * 1024 * 1024, # 50 MB
            'text/plain': 1 * 1024 * 1024,   # 1 MB
            'text/csv': 5 * 1024 * 1024,     # 5 MB
            'application/json': 1 * 1024 * 1024, # 1 MB
            'application/xml': 1 * 1024 * 1024,  # 1 MB
            'application/zip': 100 * 1024 * 1024, # 100 MB
            'application/x-tar': 100 * 1024 * 1024, # 100 MB
            'application/gzip': 100 * 1024 * 1024,  # 100 MB
            'text/x-python': 1 * 1024 * 1024, # 1 MB
            'text/javascript': 1 * 1024 * 1024, # 1 MB
            'text/css': 1 * 1024 * 1024,      # 1 MB
            'text/html': 1 * 1024 * 1024,     # 1 MB
        }
        
        # Максимальное количество файлов
        self.max_files_per_upload = 10
        
        # Базовые директории для загрузки
        self.upload_base_dir = Path("uploads")
        self.upload_base_dir.mkdir(exist_ok=True)
    
    def _get_mime_type_by_extension(self, extension: str) -> str:
        """Определяет MIME тип по расширению файла"""
        mime_map = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.csv': 'text/csv',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.zip': 'application/zip',
            '.tar': 'application/x-tar',
            '.gz': 'application/gzip',
            '.py': 'text/x-python',
            '.js': 'text/javascript',
            '.css': 'text/css',
            '.html': 'text/html',
            '.htm': 'text/html',
        }
        return mime_map.get(extension, 'application/octet-stream')
    
    async def validate_file(self, file_content: bytes, filename: str) -> Tuple[bool, str, Optional[str]]:
        """Валидирует загружаемый файл"""
        try:
            # Проверяем размер файла
            if len(file_content) == 0:
                return False, "File is empty", None
            
            # Проверяем расширение файла
            file_ext = Path(filename).suffix.lower()
            if file_ext in self.forbidden_extensions:
                return False, f"Forbidden file extension: {file_ext}", None
            
            # Определяем MIME тип
            if MAGIC_AVAILABLE:
                mime_type = magic.from_buffer(file_content, mime=True)
            else:
                # Fallback: определяем по расширению
                mime_type = self._get_mime_type_by_extension(file_ext)
            
            # Проверяем, разрешен ли MIME тип
            if mime_type not in self.allowed_mime_types:
                return False, f"Forbidden MIME type: {mime_type}", None
            
            # Проверяем соответствие расширения и MIME типа
            if file_ext not in self.allowed_mime_types[mime_type]:
                return False, f"File extension {file_ext} doesn't match MIME type {mime_type}", None
            
            # Проверяем размер файла
            max_size = self.max_file_sizes.get(mime_type, 1 * 1024 * 1024)  # 1 MB по умолчанию
            if len(file_content) > max_size:
                return False, f"File too large. Maximum size: {max_size} bytes", None
            
            # Дополнительные проверки для изображений
            if mime_type.startswith('image/'):
                if not await self._validate_image(file_content):
                    return False, "Invalid or corrupted image", None
            
            # Дополнительные проверки для архивов
            if mime_type in ['application/zip', 'application/x-tar', 'application/gzip']:
                if not await self._validate_archive(file_content, mime_type):
                    return False, "Invalid or potentially dangerous archive", None
            
            return True, "File is valid", mime_type
            
        except Exception as e:
            logger.error(f"Error validating file {filename}: {e}")
            return False, f"Validation error: {str(e)}", None
    
    async def _validate_image(self, file_content: bytes) -> bool:
        """Валидирует изображение"""
        try:
            if PIL_AVAILABLE:
                # Проверяем с помощью PIL
                image = Image.open(io.BytesIO(file_content))
                image.verify()
                
                # Проверяем размеры изображения
                if image.width > 10000 or image.height > 10000:
                    return False
                
                return True
            else:
                # Fallback: базовая проверка заголовков
                if file_content.startswith(b'\x89PNG') or file_content.startswith(b'\xff\xd8\xff'):
                    return True
                return False
            
        except Exception as e:
            logger.warning(f"Image validation failed: {e}")
            return False
    
    async def _validate_archive(self, file_content: bytes, mime_type: str) -> bool:
        """Валидирует архив"""
        try:
            if mime_type == 'application/zip':
                with zipfile.ZipFile(io.BytesIO(file_content)) as zip_file:
                    # Проверяем количество файлов в архиве
                    if len(zip_file.namelist()) > 1000:
                        return False
                    
                    # Проверяем на path traversal
                    for name in zip_file.namelist():
                        if '..' in name or name.startswith('/'):
                            return False
                        
                        # Проверяем расширения файлов в архиве
                        file_ext = Path(name).suffix.lower()
                        if file_ext in self.forbidden_extensions:
                            return False
            
            elif mime_type == 'application/x-tar':
                with tarfile.open(fileobj=io.BytesIO(file_content)) as tar_file:
                    # Проверяем количество файлов в архиве
                    if len(tar_file.getnames()) > 1000:
                        return False
                    
                    # Проверяем на path traversal
                    for name in tar_file.getnames():
                        if '..' in name or name.startswith('/'):
                            return False
                        
                        # Проверяем расширения файлов в архиве
                        file_ext = Path(name).suffix.lower()
                        if file_ext in self.forbidden_extensions:
                            return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Archive validation failed: {e}")
            return False
    
    async def save_file(self, file_content: bytes, filename: str, user_id: str, project_id: str) -> Tuple[bool, str, Optional[str]]:
        """Безопасно сохраняет файл"""
        try:
            # Валидируем файл
            is_valid, message, mime_type = await self.validate_file(file_content, filename)
            if not is_valid:
                return False, message, None
            
            # Создаем безопасное имя файла
            safe_filename = self._generate_safe_filename(filename)
            
            # Создаем директорию для пользователя и проекта
            user_dir = self.upload_base_dir / user_id / project_id
            user_dir.mkdir(parents=True, exist_ok=True)
            
            # Генерируем уникальное имя файла
            file_path = user_dir / safe_filename
            counter = 1
            while file_path.exists():
                name_part = file_path.stem
                ext_part = file_path.suffix
                file_path = user_dir / f"{name_part}_{counter}{ext_part}"
                counter += 1
            
            # Сохраняем файл
            if AIOFILES_AVAILABLE:
                async with aiofiles.open(file_path, 'wb') as f:
                    await f.write(file_content)
            else:
                # Fallback: синхронное сохранение
                with open(file_path, 'wb') as f:
                    f.write(file_content)
            
            # Вычисляем хеш файла
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            logger.info(f"File saved: {file_path} (hash: {file_hash})")
            
            return True, "File saved successfully", str(file_path)
            
        except Exception as e:
            logger.error(f"Error saving file {filename}: {e}")
            return False, f"Error saving file: {str(e)}", None
    
    def _generate_safe_filename(self, filename: str) -> str:
        """Генерирует безопасное имя файла"""
        # Убираем опасные символы
        safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
        safe_filename = ''.join(c for c in filename if c in safe_chars)
        
        # Ограничиваем длину
        if len(safe_filename) > 100:
            name_part = safe_filename[:90]
            ext_part = Path(filename).suffix
            safe_filename = name_part + ext_part
        
        # Если имя файла пустое, генерируем случайное
        if not safe_filename:
            safe_filename = f"file_{secrets.token_hex(8)}"
        
        return safe_filename
    
    async def scan_file_for_malware(self, file_path: str) -> Tuple[bool, str]:
        """Сканирует файл на malware (заглушка)"""
        # В реальном приложении здесь должен быть интеграция с антивирусом
        # Например, ClamAV или VirusTotal API
        
        try:
            # Простая проверка на подозрительные паттерны
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Читаем первые 1024 байта
                
                # Проверяем на подозрительные строки
                suspicious_patterns = [
                    b'<script',
                    b'javascript:',
                    b'eval(',
                    b'exec(',
                    b'system(',
                    b'cmd.exe',
                    b'/bin/sh',
                    b'powershell'
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in content.lower():
                        return False, f"Suspicious pattern detected: {pattern.decode()}"
            
            return True, "File appears to be clean"
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return False, f"Scan error: {str(e)}"
    
    def get_file_info(self, file_path: str) -> Optional[Dict]:
        """Получает информацию о файле"""
        try:
            path = Path(file_path)
            if not path.exists():
                return None
            
            stat = path.stat()
            
            return {
                "filename": path.name,
                "size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "extension": path.suffix,
                "mime_type": magic.from_file(str(path), mime=True) if MAGIC_AVAILABLE else self._get_mime_type_by_extension(path.suffix)
            }
            
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            return None
    
    async def delete_file(self, file_path: str) -> bool:
        """Безопасно удаляет файл"""
        try:
            path = Path(file_path)
            
            # Проверяем, что файл находится в разрешенной директории
            if not str(path.resolve()).startswith(str(self.upload_base_dir.resolve())):
                logger.warning(f"Attempt to delete file outside upload directory: {file_path}")
                return False
            
            if path.exists():
                path.unlink()
                logger.info(f"File deleted: {file_path}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")
            return False

# Глобальный экземпляр
file_upload_security = FileUploadSecurity()

# Удобные функции
async def validate_file(file_content: bytes, filename: str) -> Tuple[bool, str, Optional[str]]:
    """Валидирует загружаемый файл"""
    return await file_upload_security.validate_file(file_content, filename)

async def save_file(file_content: bytes, filename: str, user_id: str, project_id: str) -> Tuple[bool, str, Optional[str]]:
    """Безопасно сохраняет файл"""
    return await file_upload_security.save_file(file_content, filename, user_id, project_id)

async def scan_file_for_malware(file_path: str) -> Tuple[bool, str]:
    """Сканирует файл на malware"""
    return await file_upload_security.scan_file_for_malware(file_path)

def get_file_info(file_path: str) -> Optional[Dict]:
    """Получает информацию о файле"""
    return file_upload_security.get_file_info(file_path)

async def delete_file(file_path: str) -> bool:
    """Безопасно удаляет файл"""
    return await file_upload_security.delete_file(file_path)