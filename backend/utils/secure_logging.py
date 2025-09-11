"""
Безопасное логирование - убирает чувствительные данные из логов
"""

import re
import logging
from typing import Any, Dict, List, Optional
from functools import wraps

class SecureLogger:
    """Безопасный логгер, который санитизирует чувствительные данные"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        
        # Паттерны для поиска чувствительных данных
        self.sensitive_patterns = [
            r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'(?i)(token|key|secret)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'(?i)(api_key|apikey)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'(?i)(jwt|bearer)\s*["\']?([^"\'\s]+)["\']?',
            r'(?i)(email)\s*[:=]\s*["\']?([^"\'\s@]+@[^"\'\s]+)["\']?',
            r'(?i)(credit_card|cc_number)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'(?i)(ssn|social_security)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
        ]
        
        # Список ключей, которые нужно санитизировать
        self.sensitive_keys = [
            'password', 'passwd', 'pwd', 'token', 'key', 'secret',
            'api_key', 'apikey', 'jwt', 'bearer', 'email', 'credit_card',
            'cc_number', 'ssn', 'social_security', 'auth_token', 'access_token',
            'refresh_token', 'session_id', 'cookie', 'authorization'
        ]
    
    def _sanitize_string(self, text: str) -> str:
        """Санитизирует строку, убирая чувствительные данные"""
        if not isinstance(text, str):
            return str(text)
        
        # Заменяем по паттернам
        for pattern in self.sensitive_patterns:
            text = re.sub(pattern, r'\1=***REDACTED***', text)
        
        return text
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Санитизирует словарь, убирая чувствительные ключи"""
        sanitized = {}
        
        for key, value in data.items():
            # Проверяем ключ
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in self.sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = self._sanitize_list(value)
            elif isinstance(value, str):
                sanitized[key] = self._sanitize_string(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_list(self, data: List[Any]) -> List[Any]:
        """Санитизирует список"""
        sanitized = []
        
        for item in data:
            if isinstance(item, dict):
                sanitized.append(self._sanitize_dict(item))
            elif isinstance(item, list):
                sanitized.append(self._sanitize_list(item))
            elif isinstance(item, str):
                sanitized.append(self._sanitize_string(item))
            else:
                sanitized.append(item)
        
        return sanitized
    
    def _sanitize_args(self, *args, **kwargs) -> tuple:
        """Санитизирует аргументы для логирования"""
        sanitized_args = []
        
        for arg in args:
            if isinstance(arg, dict):
                sanitized_args.append(self._sanitize_dict(arg))
            elif isinstance(arg, list):
                sanitized_args.append(self._sanitize_list(arg))
            elif isinstance(arg, str):
                sanitized_args.append(self._sanitize_string(arg))
            else:
                sanitized_args.append(arg)
        
        sanitized_kwargs = self._sanitize_dict(kwargs)
        
        return tuple(sanitized_args), sanitized_kwargs
    
    def debug(self, message: str, *args, **kwargs):
        """Безопасное логирование DEBUG"""
        sanitized_args, sanitized_kwargs = self._sanitize_args(*args, **kwargs)
        self.logger.debug(message, *sanitized_args, **sanitized_kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """Безопасное логирование INFO"""
        sanitized_args, sanitized_kwargs = self._sanitize_args(*args, **kwargs)
        self.logger.info(message, *sanitized_args, **sanitized_kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Безопасное логирование WARNING"""
        sanitized_args, sanitized_kwargs = self._sanitize_args(*args, **kwargs)
        self.logger.warning(message, *sanitized_args, **sanitized_kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """Безопасное логирование ERROR"""
        sanitized_args, sanitized_kwargs = self._sanitize_args(*args, **kwargs)
        self.logger.error(message, *sanitized_args, **sanitized_kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        """Безопасное логирование CRITICAL"""
        sanitized_args, sanitized_kwargs = self._sanitize_args(*args, **kwargs)
        self.logger.critical(message, *sanitized_args, **sanitized_kwargs)

def get_secure_logger(name: str) -> SecureLogger:
    """Получить безопасный логгер"""
    return SecureLogger(name)

def secure_log(func):
    """Декоратор для безопасного логирования в функциях"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_secure_logger(func.__module__)
        logger.info(f"Calling {func.__name__}")
        
        try:
            result = func(*args, **kwargs)
            logger.info(f"Successfully completed {func.__name__}")
            return result
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}")
            raise
    
    return wrapper

# Глобальные функции для удобства
def secure_debug(name: str, message: str, *args, **kwargs):
    """Безопасное логирование DEBUG"""
    logger = get_secure_logger(name)
    logger.debug(message, *args, **kwargs)

def secure_info(name: str, message: str, *args, **kwargs):
    """Безопасное логирование INFO"""
    logger = get_secure_logger(name)
    logger.info(message, *args, **kwargs)

def secure_warning(name: str, message: str, *args, **kwargs):
    """Безопасное логирование WARNING"""
    logger = get_secure_logger(name)
    logger.warning(message, *args, **kwargs)

def secure_error(name: str, message: str, *args, **kwargs):
    """Безопасное логирование ERROR"""
    logger = get_secure_logger(name)
    logger.error(message, *args, **kwargs)

def secure_critical(name: str, message: str, *args, **kwargs):
    """Безопасное логирование CRITICAL"""
    logger = get_secure_logger(name)
    logger.critical(message, *args, **kwargs)