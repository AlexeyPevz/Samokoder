"""
Валидатор входных данных для API
Обеспечивает безопасную валидацию и санитизацию данных
"""

import re
import html
from typing import Any, Dict, List, Optional, Union
from urllib.parse import unquote
import structlog

logger = structlog.get_logger(__name__)

class InputValidator:
    """Класс для валидации и санитизации входных данных"""
    
    # Регулярные выражения для валидации
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    SAFE_STRING_PATTERN = re.compile(r'^[a-zA-Z0-9\s._-]+$')
    
    # Максимальные длины полей
    MAX_EMAIL_LENGTH = 254
    MAX_PASSWORD_LENGTH = 1000
    MAX_NAME_LENGTH = 255
    MAX_DESCRIPTION_LENGTH = 10000
    MAX_MESSAGE_LENGTH = 50000
    MAX_PATH_LENGTH = 1000
    
    # Минимальные длины полей
    MIN_PASSWORD_LENGTH = 6
    MIN_NAME_LENGTH = 1
    
    @classmethod
    def validate_email(cls, email: str) -> tuple[bool, str]:
        """
        Валидация email адреса.
        
        Args:
            email: Email для валидации
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not email:
            return False, "Email не может быть пустым"
        
        if len(email) > cls.MAX_EMAIL_LENGTH:
            return False, f"Email не может быть длиннее {cls.MAX_EMAIL_LENGTH} символов"
        
        if not cls.EMAIL_PATTERN.match(email):
            return False, "Неверный формат email адреса"
        
        # Проверка на подозрительные символы
        if any(char in email for char in ['<', '>', '"', "'", '&']):
            return False, "Email содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def validate_password(cls, password: str) -> tuple[bool, str]:
        """
        Валидация пароля.
        
        Args:
            password: Пароль для валидации
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not password:
            return False, "Пароль не может быть пустым"
        
        if len(password) < cls.MIN_PASSWORD_LENGTH:
            return False, f"Пароль должен содержать минимум {cls.MIN_PASSWORD_LENGTH} символов"
        
        if len(password) > cls.MAX_PASSWORD_LENGTH:
            return False, f"Пароль не может быть длиннее {cls.MAX_PASSWORD_LENGTH} символов"
        
        # Проверка на подозрительные символы
        if any(char in password for char in ['<', '>', '"', "'", '&', '\x00']):
            return False, "Пароль содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def validate_name(cls, name: str, field_name: str = "Название") -> tuple[bool, str]:
        """
        Валидация названия.
        
        Args:
            name: Название для валидации
            field_name: Название поля для ошибки
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not name:
            return False, f"{field_name} не может быть пустым"
        
        if len(name) < cls.MIN_NAME_LENGTH:
            return False, f"{field_name} должно содержать минимум {cls.MIN_NAME_LENGTH} символ"
        
        if len(name) > cls.MAX_NAME_LENGTH:
            return False, f"{field_name} не может быть длиннее {cls.MAX_NAME_LENGTH} символов"
        
        # Проверка на подозрительные символы
        if any(char in name for char in ['<', '>', '"', "'", '&', '\x00']):
            return False, f"{field_name} содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def validate_description(cls, description: str) -> tuple[bool, str]:
        """
        Валидация описания.
        
        Args:
            description: Описание для валидации
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if description is None:
            return True, ""  # Описание может быть пустым
        
        if len(description) > cls.MAX_DESCRIPTION_LENGTH:
            return False, f"Описание не может быть длиннее {cls.MAX_DESCRIPTION_LENGTH} символов"
        
        # Проверка на подозрительные символы
        if any(char in description for char in ['<', '>', '\x00']):
            return False, "Описание содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def validate_message(cls, message: str) -> tuple[bool, str]:
        """
        Валидация сообщения чата.
        
        Args:
            message: Сообщение для валидации
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not message:
            return False, "Сообщение не может быть пустым"
        
        if len(message) > cls.MAX_MESSAGE_LENGTH:
            return False, f"Сообщение не может быть длиннее {cls.MAX_MESSAGE_LENGTH} символов"
        
        # Проверка на подозрительные символы
        if any(char in message for char in ['\x00']):
            return False, "Сообщение содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def validate_uuid(cls, uuid_str: str, field_name: str = "ID") -> tuple[bool, str]:
        """
        Валидация UUID.
        
        Args:
            uuid_str: UUID строка для валидации
            field_name: Название поля для ошибки
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not uuid_str:
            return False, f"{field_name} не может быть пустым"
        
        if not cls.UUID_PATTERN.match(uuid_str):
            return False, f"Неверный формат {field_name}"
        
        return True, ""
    
    @classmethod
    def validate_path(cls, path: str) -> tuple[bool, str]:
        """
        Валидация пути к файлу.
        
        Args:
            path: Путь для валидации
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not path:
            return False, "Путь не может быть пустым"
        
        if len(path) > cls.MAX_PATH_LENGTH:
            return False, f"Путь не может быть длиннее {cls.MAX_PATH_LENGTH} символов"
        
        # Проверка на path traversal атаки
        if any(pattern in path for pattern in ['../', '..\\', '..%2f', '..%5c']):
            return False, "Путь содержит недопустимые символы"
        
        # Проверка на null байты
        if '\x00' in path:
            return False, "Путь содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def sanitize_string(cls, text: str) -> str:
        """
        Санитизация строки от потенциально опасных символов.
        
        Args:
            text: Текст для санитизации
            
        Returns:
            str: Санитизированный текст
        """
        if not text:
            return text
        
        # HTML экранирование
        text = html.escape(text, quote=True)
        
        # Удаление null байтов
        text = text.replace('\x00', '')
        
        # Удаление лишних пробелов
        text = ' '.join(text.split())
        
        return text
    
    @classmethod
    def validate_json_data(cls, data: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Валидация JSON данных на предмет подозрительного содержимого.
        
        Args:
            data: JSON данные для валидации
            
        Returns:
            tuple: (is_valid, error_messages)
        """
        errors = []
        
        # Рекурсивная проверка словаря
        def check_dict(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    check_dict(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    check_dict(item, current_path)
            elif isinstance(obj, str):
                # Проверка строк на подозрительное содержимое
                if any(pattern in obj.lower() for pattern in [
                    'script', 'javascript:', 'vbscript:', 'onload', 'onerror',
                    'onclick', 'onmouseover', 'eval(', 'expression('
                ]):
                    errors.append(f"Подозрительное содержимое в {current_path}")
                
                # Проверка на SQL инъекции
                if any(pattern in obj.upper() for pattern in [
                    'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'ALTER', 'CREATE', 'EXEC', 'EXECUTE'
                ]):
                    errors.append(f"Возможная SQL инъекция в {current_path}")
        
        check_dict(data)
        
        return len(errors) == 0, errors
    
    @classmethod
    def validate_request_size(cls, content_length: int, max_size: int = 10 * 1024 * 1024) -> tuple[bool, str]:
        """
        Валидация размера запроса.
        
        Args:
            content_length: Размер контента в байтах
            max_size: Максимальный допустимый размер
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if content_length > max_size:
            return False, f"Размер запроса превышает максимально допустимый ({max_size // (1024*1024)}MB)"
        
        return True, ""

# Глобальный экземпляр валидатора
validator = InputValidator()