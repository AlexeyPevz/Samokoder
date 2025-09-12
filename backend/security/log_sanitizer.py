"""
Модуль для санитизации и валидации данных в логах
Предотвращает инъекции и утечки чувствительных данных
"""

import re
import html
import json
from typing import Any, Dict, List, Union, Optional
from urllib.parse import quote


class LogSanitizer:
    """Класс для санитизации данных перед логированием"""
    
    # Регулярные выражения для чувствительных данных
    SENSITIVE_PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'password="***"'),
        (r'token["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'token="***"'),
        (r'key["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'key="***"'),
        (r'secret["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'secret="***"'),
        (r'api_key["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'api_key="***"'),
        (r'access_token["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'access_token="***"'),
        (r'refresh_token["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'refresh_token="***"'),
        (r'authorization["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'authorization="***"'),
        (r'bearer["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'bearer="***"'),
    ]
    
    # Паттерны для потенциально опасных данных
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'data:text/html',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
    ]
    
    # Максимальная длина строки в логах
    MAX_LOG_LENGTH = 1000
    
    @classmethod
    def sanitize_string(cls, value: str) -> str:
        """Санитизирует строку для безопасного логирования"""
        if not isinstance(value, str):
            value = str(value)
        
        # Обрезаем слишком длинные строки
        if len(value) > cls.MAX_LOG_LENGTH:
            value = value[:cls.MAX_LOG_LENGTH] + "...[truncated]"
        
        # Удаляем чувствительные данные
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)
        
        # Проверяем на опасные паттерны
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                value = "[POTENTIALLY_DANGEROUS_CONTENT_REMOVED]"
                break
        
        # HTML экранирование
        value = html.escape(value, quote=False)
        
        # Удаляем управляющие символы
        value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
        
        return value
    
    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Санитизирует словарь для безопасного логирования"""
        if not isinstance(data, dict):
            return cls.sanitize_string(str(data))
        
        sanitized = {}
        for key, value in data.items():
            # Санитизируем ключ
            safe_key = cls.sanitize_string(str(key))
            
            # Санитизируем значение
            if isinstance(value, dict):
                safe_value = cls.sanitize_dict(value)
            elif isinstance(value, list):
                safe_value = cls.sanitize_list(value)
            elif isinstance(value, str):
                safe_value = cls.sanitize_string(value)
            else:
                safe_value = cls.sanitize_string(str(value))
            
            sanitized[safe_key] = safe_value
        
        return sanitized
    
    @classmethod
    def sanitize_list(cls, data: List[Any]) -> List[Any]:
        """Санитизирует список для безопасного логирования"""
        if not isinstance(data, list):
            return cls.sanitize_string(str(data))
        
        sanitized = []
        for item in data:
            if isinstance(item, dict):
                sanitized.append(cls.sanitize_dict(item))
            elif isinstance(item, list):
                sanitized.append(cls.sanitize_list(item))
            elif isinstance(item, str):
                sanitized.append(cls.sanitize_string(item))
            else:
                sanitized.append(cls.sanitize_string(str(item)))
        
        return sanitized
    
    @classmethod
    def sanitize_any(cls, data: Any) -> Any:
        """Универсальная функция санитизации"""
        if isinstance(data, dict):
            return cls.sanitize_dict(data)
        elif isinstance(data, list):
            return cls.sanitize_list(data)
        elif isinstance(data, str):
            return cls.sanitize_string(data)
        else:
            return cls.sanitize_string(str(data))
    
    @classmethod
    def safe_json_dumps(cls, data: Any) -> str:
        """Безопасная сериализация в JSON"""
        try:
            sanitized_data = cls.sanitize_any(data)
            return json.dumps(sanitized_data, ensure_ascii=False, separators=(',', ':'))
        except (TypeError, ValueError) as e:
            return f'{{"error": "JSON serialization failed: {str(e)}"}}'
    
    @classmethod
    def validate_log_level(cls, level: str) -> str:
        """Валидирует уровень логирования"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level.upper() in valid_levels:
            return level.upper()
        return 'INFO'
    
    @classmethod
    def validate_log_message(cls, message: str) -> str:
        """Валидирует сообщение лога"""
        if not isinstance(message, str):
            message = str(message)
        
        # Проверяем на пустые сообщения
        if not message.strip():
            return "[EMPTY_MESSAGE]"
        
        # Санитизируем сообщение
        return cls.sanitize_string(message)
    
    @classmethod
    def create_safe_log_data(cls, level: str, message: str, **kwargs) -> Dict[str, Any]:
        """Создает безопасные данные для логирования"""
        return {
            'level': cls.validate_log_level(level),
            'message': cls.validate_log_message(message),
            'timestamp': cls.sanitize_string(str(kwargs.get('timestamp', ''))),
            'module': cls.sanitize_string(str(kwargs.get('module', ''))),
            'function': cls.sanitize_string(str(kwargs.get('function', ''))),
            'line': cls.sanitize_string(str(kwargs.get('line', ''))),
            'extra': cls.sanitize_dict(kwargs.get('extra', {}))
        }


class SecureLogger:
    """Безопасный логгер с автоматической санитизацией"""
    
    def __init__(self, name: str):
        self.name = name
        self.sanitizer = LogSanitizer()
    
    def _log(self, level: str, message: str, **kwargs):
        """Внутренний метод логирования с санитизацией"""
        safe_data = self.sanitizer.create_safe_log_data(level, message, **kwargs)
        
        # Здесь можно добавить отправку в систему логирования
        # Например, в ELK, Splunk или другую систему
        print(f"[{safe_data['level']}] {safe_data['message']}")
        
        if safe_data['extra']:
            print(f"Extra data: {self.sanitizer.safe_json_dumps(safe_data['extra'])}")
    
    def debug(self, message: str, **kwargs):
        """Логирование уровня DEBUG"""
        self._log('DEBUG', message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Логирование уровня INFO"""
        self._log('INFO', message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Логирование уровня WARNING"""
        self._log('WARNING', message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Логирование уровня ERROR"""
        self._log('ERROR', message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Логирование уровня CRITICAL"""
        self._log('CRITICAL', message, **kwargs)


# Глобальный экземпляр санитизатора
log_sanitizer = LogSanitizer()

# Функции для удобного использования
def sanitize_for_log(data: Any) -> Any:
    """Санитизирует данные для безопасного логирования"""
    return log_sanitizer.sanitize_any(data)

def safe_log_message(message: str) -> str:
    """Санитизирует сообщение лога"""
    return log_sanitizer.validate_log_message(message)

def safe_json_log(data: Any) -> str:
    """Безопасная сериализация в JSON для логов"""
    return log_sanitizer.safe_json_dumps(data)