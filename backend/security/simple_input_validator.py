"""
Упрощенный валидатор входных данных без внешних зависимостей
"""

import re
import html
import json
import logging
from typing import Any, Dict, List, Optional, Union, Tuple
from urllib.parse import unquote

logger = logging.getLogger(__name__)

class SimpleInputValidator:
    """Упрощенный валидатор входных данных"""
    
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
            r'\.\.\\\\',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'\.\.%2f',
            r'\.\.%5c',
        ]
    
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
        
        # Базовая очистка HTML
        return html.escape(value)
    
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
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Валидирует силу пароля"""
        errors = []
        
        if not isinstance(password, str):
            errors.append("Password must be a string")
            return False, errors
        
        if len(password) < 12:
            errors.append("Password must be at least 12 characters long")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            errors.append("Password must contain at least one special character")
        
        # Проверка на общие пароли
        common_passwords = [
            'password', '123456', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', '1234567890'
        ]
        
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        return len(errors) == 0, errors
    
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
simple_validator = SimpleInputValidator()

# Удобные функции
def validate_sql_input(value: str) -> bool:
    """Проверяет входные данные на SQL injection"""
    return simple_validator.validate_sql_input(value)

def validate_xss_input(value: str) -> bool:
    """Проверяет входные данные на XSS"""
    return simple_validator.validate_xss_input(value)

def validate_path_traversal(value: str) -> bool:
    """Проверяет на path traversal атаки"""
    return simple_validator.validate_path_traversal(value)

def sanitize_html(value: str) -> str:
    """Санитизирует HTML контент"""
    return simple_validator.sanitize_html(value)

def validate_email(email: str) -> bool:
    """Валидирует email адрес"""
    return simple_validator.validate_email(email)

def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """Валидирует силу пароля"""
    return simple_validator.validate_password_strength(password)

def validate_project_name(name: str) -> bool:
    """Валидирует имя проекта"""
    return simple_validator.validate_project_name(name)