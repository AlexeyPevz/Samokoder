"""
Упрощенная безопасная загрузка файлов без внешних зависимостей
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

logger = logging.getLogger(__name__)

class SimpleFileUploadSecurity:
    """Упрощенная безопасная загрузка файлов"""
    
    def __init__(self):
        # Разрешенные расширения файлов
        self.allowed_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg',
            '.pdf', '.txt', '.csv', '.json', '.xml',
            '.zip', '.tar', '.gz',
            '.py', '.js', '.css', '.html', '.htm'
        }
        
        # Запрещенные расширения
        self.forbidden_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            '.jar', '.php', '.asp', '.aspx', '.jsp', '.sh', '.ps1', '.psm1'
        }
        
        # Максимальные размеры файлов (в байтах)
        self.max_file_sizes = {
            '.jpg': 10 * 1024 * 1024,   # 10 MB
            '.jpeg': 10 * 1024 * 1024,  # 10 MB
            '.png': 10 * 1024 * 1024,   # 10 MB
            '.gif': 5 * 1024 * 1024,    # 5 MB
            '.webp': 10 * 1024 * 1024,  # 10 MB
            '.svg': 1 * 1024 * 1024,    # 1 MB
            '.pdf': 50 * 1024 * 1024,   # 50 MB
            '.txt': 1 * 1024 * 1024,    # 1 MB
            '.csv': 5 * 1024 * 1024,    # 5 MB
            '.json': 1 * 1024 * 1024,   # 1 MB
            '.xml': 1 * 1024 * 1024,    # 1 MB
            '.zip': 100 * 1024 * 1024,  # 100 MB
            '.tar': 100 * 1024 * 1024,  # 100 MB
            '.gz': 100 * 1024 * 1024,   # 100 MB
            '.py': 1 * 1024 * 1024,     # 1 MB
            '.js': 1 * 1024 * 1024,     # 1 MB
            '.css': 1 * 1024 * 1024,    # 1 MB
            '.html': 1 * 1024 * 1024,   # 1 MB
            '.htm': 1 * 1024 * 1024,    # 1 MB
        }
        
        # Максимальное количество файлов
        self.max_files_per_upload = 10
        
        # Базовые директории для загрузки
        self.upload_base_dir = Path("uploads")
        self.upload_base_dir.mkdir(exist_ok=True)
    
    def validate_file(self, file_content: bytes, filename: str) -> Tuple[bool, str, Optional[str]]:
        """Валидирует загружаемый файл"""
        try:
            # Проверяем размер файла
            if len(file_content) == 0:
                return False, "File is empty", None
            
            # Проверяем расширение файла
            file_ext = Path(filename).suffix.lower()
            if file_ext in self.forbidden_extensions:
                return False, f"Forbidden file extension: {file_ext}", None
            
            if file_ext not in self.allowed_extensions:
                return False, f"Unsupported file extension: {file_ext}", None
            
            # Проверяем размер файла
            max_size = self.max_file_sizes.get(file_ext, 1 * 1024 * 1024)  # 1 MB по умолчанию
            if len(file_content) > max_size:
                return False, f"File too large. Maximum size: {max_size} bytes", None
            
            # Дополнительные проверки для изображений
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
                if not self._validate_image(file_content):
                    return False, "Invalid or corrupted image", None
            
            # Дополнительные проверки для архивов
            if file_ext in ['.zip', '.tar', '.gz']:
                if not self._validate_archive(file_content, file_ext):
                    return False, "Invalid or potentially dangerous archive", None
            
            return True, "File is valid", file_ext
            
        except Exception as e:
            logger.error(f"Error validating file {filename}: {e}")
            return False, f"Validation error: {str(e)}", None
    
    def _validate_image(self, file_content: bytes) -> bool:
        """Валидирует изображение"""
        try:
            # Базовая проверка заголовков различных форматов
            image_signatures = [
                b'\x89PNG',           # PNG
                b'\xff\xd8\xff',      # JPEG
                b'GIF87a',            # GIF87a
                b'GIF89a',            # GIF89a
                b'RIFF',              # WebP (начинается с RIFF)
                b'<svg',              # SVG (текстовый формат)
                b'<?xml',             # SVG может начинаться с XML
            ]
            
            for signature in image_signatures:
                if file_content.startswith(signature):
                    return True
            
            # Дополнительная проверка для WebP
            if b'WEBP' in file_content[:20]:
                return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Image validation failed: {e}")
            return False
    
    def _validate_archive(self, file_content: bytes, extension: str) -> bool:
        """Валидирует архив"""
        try:
            if extension == '.zip':
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
            
            elif extension == '.tar':
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
    
    def save_file(self, file_content: bytes, filename: str, user_id: str, project_id: str) -> Tuple[bool, str, Optional[str]]:
        """Безопасно сохраняет файл"""
        try:
            # Валидируем файл
            is_valid, message, file_ext = self.validate_file(file_content, filename)
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
        # Убираем опасные символы и пути
        safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
        safe_filename = ''.join(c for c in filename if c in safe_chars)
        
        # Убираем множественные точки и слеши
        safe_filename = safe_filename.replace('..', '').replace('/', '').replace('\\', '')
        
        # Ограничиваем длину
        if len(safe_filename) > 100:
            name_part = safe_filename[:90]
            ext_part = Path(filename).suffix
            safe_filename = name_part + ext_part
        
        # Если имя файла пустое, генерируем случайное
        if not safe_filename:
            safe_filename = f"file_{secrets.token_hex(8)}"
        
        return safe_filename
    
    def scan_file_for_malware(self, file_path: str) -> Tuple[bool, str]:
        """Сканирует файл на malware (заглушка)"""
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
                "mime_type": self._get_mime_type_by_extension(path.suffix)
            }
            
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            return None
    
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
    
    def delete_file(self, file_path: str) -> bool:
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
simple_file_upload_security = SimpleFileUploadSecurity()

# Удобные функции
def validate_file(file_content: bytes, filename: str) -> Tuple[bool, str, Optional[str]]:
    """Валидирует загружаемый файл"""
    return simple_file_upload_security.validate_file(file_content, filename)

def save_file(file_content: bytes, filename: str, user_id: str, project_id: str) -> Tuple[bool, str, Optional[str]]:
    """Безопасно сохраняет файл"""
    return simple_file_upload_security.save_file(file_content, filename, user_id, project_id)

def scan_file_for_malware(file_path: str) -> Tuple[bool, str]:
    """Сканирует файл на malware"""
    return simple_file_upload_security.scan_file_for_malware(file_path)

def get_file_info(file_path: str) -> Optional[Dict]:
    """Получает информацию о файле"""
    return simple_file_upload_security.get_file_info(file_path)

def delete_file(file_path: str) -> bool:
    """Безопасно удаляет файл"""
    return simple_file_upload_security.delete_file(file_path)