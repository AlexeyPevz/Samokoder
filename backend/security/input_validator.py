"""
Безопасный валидатор входных данных
Защита от SQL injection, XSS, и других атак
"""

import re
import html
import json
import logging
from typing import Any, Dict, List, Optional, Union, Tuple
from urllib.parse import unquote

# Опциональные импорты с fallback
try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False
    bleach = None

try:
    from pydantic import BaseModel, validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = None
    validator = None

logger = logging.getLogger(__name__)

class SecureInputValidator:
    """Безопасный валидатор входных данных"""
    
    def __init__(self):
        # Паттерны для опасных SQL конструкций
        self.sql_patterns = [
            r'(?i)(union\s+select|union\s+all\s+select)',
            r'(?i)(drop\s+table|truncate\s+table|alter\s+table)',
            r'(?i)(exec\s*\(|execute\s*\(|sp_executesql)',
            r'(?i)(--|\#|\/\*|\*\/)',
            r'(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)',
            r'(?i)(\'\s*or\s*\'\s*=\s*\'|\"\s*or\s*\"\s*=\s*\")',
            r'(?i)(insert\s+into.*values|update\s+.*set.*where|delete\s+from.*where)',
            # Дополнительные паттерны для критических атак
            r'(?i)(\d+\'\s*or\s*\'\d+\'\s*=\s*\'\d+)',  # 1' OR '1'='1
            r'(?i)(\d+\s*;\s*delete\s+from)',  # 1; DELETE FROM
            r'(?i)(\d+\s*;\s*drop\s+table)',  # 1; DROP TABLE
            r'(?i)(\d+\s*;\s*update\s+)',  # 1; UPDATE
            r'(?i)(\d+\s*;\s*insert\s+into)',  # 1; INSERT INTO
            r'(?i)(admin\'\s*--)',  # admin'--
            r'(?i)(\'\s*;\s*drop\s+table)',  # '; DROP TABLE
            r'(?i)(\'\s*;\s*delete\s+from)',  # '; DELETE FROM
        ]
        
        # Паттерны для XSS атак
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'<style[^>]*>',
        ]
        
        # Паттерны для path traversal
        self.path_traversal_patterns = [
            r'\.\./',
            r'\.\.\\\\',  # ..\\
            r'\.\.\\',    # ..\ (одинарный слеш)
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'\.\.%2f',
            r'\.\.%5c',
            # Дополнительные паттерны для Windows
            r'\.\.\\\.\.\\',  # ..\..\
            r'\.\./\.\./',    # ../../
            r'\.\.\\[^/]*\\', # ..\anything\
            r'\.\./[^/]*/',   # ../anything/
        ]
        
        # Разрешенные HTML теги для bleach
        self.allowed_tags = [
            'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'blockquote', 'code', 'pre'
        ]
        
        # Разрешенные HTML атрибуты
        self.allowed_attributes = {
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'title', 'width', 'height'],
        }
    
    def validate_sql_input(self, value: str) -> bool:
        """Проверяет входные данные на SQL injection"""
        if not isinstance(value, str):
            return True
        
        # Декодируем URL-кодированные символы
        decoded_value = unquote(value)
        
        # Проверяем на SQL паттерны
        for pattern in self.sql_patterns:
            if re.search(pattern, decoded_value, re.IGNORECASE):
                logger.warning(f"SQL injection attempt detected: {pattern}")
                return False
        
        return True
    
    def validate_xss_input(self, value: str) -> bool:
        """Проверяет входные данные на XSS"""
        if not isinstance(value, str):
            return True
        
        # Проверяем на XSS паттерны
        for pattern in self.xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"XSS attempt detected: {pattern}")
                return False
        
        return True
    
    def validate_path_traversal(self, value: str) -> bool:
        """Проверяет на path traversal атаки"""
        if not isinstance(value, str):
            return True
        
        # Декодируем URL-кодированные символы
        decoded_value = unquote(value)
        
        # Проверяем на path traversal паттерны
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, decoded_value, re.IGNORECASE):
                logger.warning(f"Path traversal attempt detected: {pattern}")
                return False
        
        return True
    
    def sanitize_html(self, value: str) -> str:
        """Санитизирует HTML контент"""
        if not isinstance(value, str):
            return str(value)
        
        if BLEACH_AVAILABLE:
            # Используем bleach для очистки HTML
            cleaned = bleach.clean(
                value,
                tags=self.allowed_tags,
                attributes=self.allowed_attributes,
                strip=True
            )
            return cleaned
        else:
            # Fallback: базовая очистка HTML
            return html.escape(value)
    
    def sanitize_json(self, value: str) -> Optional[Dict]:
        """Безопасно парсит JSON"""
        if not isinstance(value, str):
            return None
        
        try:
            # Парсим JSON
            data = json.loads(value)
            
            # Рекурсивно санитизируем данные
            return self._sanitize_data_structure(data)
            
        except json.JSONDecodeError:
            logger.warning("Invalid JSON provided")
            return None
    
    def _sanitize_data_structure(self, data: Any) -> Any:
        """Рекурсивно санитизирует структуру данных"""
        if isinstance(data, dict):
            return {key: self._sanitize_data_structure(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_data_structure(item) for item in data]
        elif isinstance(data, str):
            # Санитизируем строки
            if not self.validate_sql_input(data):
                return "[BLOCKED: SQL injection attempt]"
            if not self.validate_xss_input(data):
                return "[BLOCKED: XSS attempt]"
            if not self.validate_path_traversal(data):
                return "[BLOCKED: Path traversal attempt]"
            return html.escape(data)
        else:
            return data
    
    def validate_email(self, email: str) -> bool:
        """Валидирует email адрес"""
        if not isinstance(email, str):
            return False
        
        # Базовый паттерн для email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False
        
        # Дополнительные проверки
        if len(email) > 254:  # RFC 5321 limit
            return False
        
        if '..' in email:  # Двойные точки недопустимы
            return False
        
        return True
    
    def _check_password_length(self, password: str) -> List[str]:
        """Проверяет длину пароля"""
        errors = []
        if len(password) < 12:
            errors.append("Password must be at least 12 characters long")
        return errors
    
    def _check_password_characters(self, password: str) -> List[str]:
        """Проверяет наличие различных типов символов"""
        errors = []
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            errors.append("Password must contain at least one special character")
        
        return errors
    
    def _check_common_passwords(self, password: str) -> List[str]:
        """Проверяет на общие пароли"""
        errors = []
        common_passwords = [
            'password', '123456', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', '1234567890'
        ]
        
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        return errors
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Валидирует силу пароля"""
        errors = []
        
        if not isinstance(password, str):
            errors.append("Password must be a string")
            return False, errors
        
        # Проверяем все критерии
        errors.extend(self._check_password_length(password))
        errors.extend(self._check_password_characters(password))
        errors.extend(self._check_common_passwords(password))
        
        return len(errors) == 0, errors
    
    def validate_api_key_format(self, api_key: str) -> bool:
        """Валидирует формат API ключа"""
        if not isinstance(api_key, str):
            return False
        
        # Проверяем длину
        if len(api_key) < 20 or len(api_key) > 200:
            return False
        
        # Проверяем на подозрительные символы
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', api_key):
            return False
        
        return True
    
    def validate_project_name(self, name: str) -> bool:
        """Валидирует имя проекта"""
        if not isinstance(name, str):
            return False
        
        # Проверяем длину
        if len(name) < 1 or len(name) > 100:
            return False
        
        # Проверяем на опасные символы
        if not re.match(r'^[a-zA-Z0-9\s\-_\.]+$', name):
            return False
        
        # Проверяем на SQL injection и XSS
        if not self.validate_sql_input(name):
            return False
        
        if not self.validate_xss_input(name):
            return False
        
        return True

# Глобальный экземпляр валидатора
secure_validator = SecureInputValidator()

# Удобные функции
def validate_sql_input(value: str) -> bool:
    """Проверяет входные данные на SQL injection"""
    return secure_validator.validate_sql_input(value)

def validate_xss_input(value: str) -> bool:
    """Проверяет входные данные на XSS"""
    return secure_validator.validate_xss_input(value)

def validate_path_traversal(value: str) -> bool:
    """Проверяет на path traversal атаки"""
    return secure_validator.validate_path_traversal(value)

def sanitize_html(value: str) -> str:
    """Санитизирует HTML контент"""
    return secure_validator.sanitize_html(value)

def sanitize_json(value: str) -> Optional[Dict]:
    """Безопасно парсит JSON"""
    return secure_validator.sanitize_json(value)

def validate_email(email: str) -> bool:
    """Валидирует email адрес"""
    return secure_validator.validate_email(email)

def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """Валидирует силу пароля"""
    return secure_validator.validate_password_strength(password)

def validate_api_key_format(api_key: str) -> bool:
    """Валидирует формат API ключа"""
    return secure_validator.validate_api_key_format(api_key)

def validate_project_name(name: str) -> bool:
    """Валидирует имя проекта"""
    return secure_validator.validate_project_name(name)