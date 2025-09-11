"""
Secure Input Validator
Улучшенная валидация входных данных с защитой от инъекций
"""

import re
import html
import bleach
from typing import Any, Dict, List, Optional, Union
from urllib.parse import unquote
import structlog
import json

logger = structlog.get_logger(__name__)

class SecureInputValidator:
    """Безопасный валидатор входных данных"""
    
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
    MIN_PASSWORD_LENGTH = 8
    MIN_NAME_LENGTH = 1
    
    # Запрещенные паттерны для SQL инъекций
    SQL_INJECTION_PATTERNS = [
        r'(?i)(union\s+select)',
        r'(?i)(drop\s+table)',
        r'(?i)(delete\s+from)',
        r'(?i)(insert\s+into)',
        r'(?i)(update\s+set)',
        r'(?i)(alter\s+table)',
        r'(?i)(create\s+table)',
        r'(?i)(exec\s*\()',
        r'(?i)(execute\s*\()',
        r'(?i)(sp_executesql)',
        r'(?i)(xp_cmdshell)',
        r'(?i)(bulk\s+insert)',
        r'(?i)(load_file\s*\()',
        r'(?i)(into\s+outfile)',
        r'(?i)(into\s+dumpfile)',
    ]
    
    # Запрещенные паттерны для XSS
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'data:text/html',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'eval\s*\(',
        r'expression\s*\(',
        r'url\s*\(',
    ]
    
    # Запрещенные паттерны для path traversal
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\\\',
        r'\\\\\.\.',
        r'%2e%2e%2f',
        r'%2e%2e%5c',
        r'\.\.%2f',
        r'\.\.%5c',
    ]
    
    @classmethod
    def validate_email(cls, email: str) -> tuple[bool, str]:
        """Безопасная валидация email"""
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
        """Безопасная валидация пароля"""
        if not password:
            return False, "Пароль не может быть пустым"
        
        if len(password) < cls.MIN_PASSWORD_LENGTH:
            return False, f"Пароль должен содержать минимум {cls.MIN_PASSWORD_LENGTH} символов"
        
        if len(password) > cls.MAX_PASSWORD_LENGTH:
            return False, f"Пароль не может быть длиннее {cls.MAX_PASSWORD_LENGTH} символов"
        
        # Проверка сложности пароля
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            return False, "Пароль должен содержать заглавные и строчные буквы, цифры и спецсимволы"
        
        # Проверка на подозрительные символы
        if any(char in password for char in ['<', '>', '"', "'", '&', '\x00']):
            return False, "Пароль содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def validate_and_sanitize_string(cls, text: str, max_length: int = 1000) -> tuple[bool, str, str]:
        """Валидация и санитизация строки"""
        if not text:
            return False, "", "Строка не может быть пустой"
        
        if len(text) > max_length:
            return False, "", f"Строка не может быть длиннее {max_length} символов"
        
        # Проверка на SQL инъекции
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return False, "", "Обнаружена попытка SQL инъекции"
        
        # Проверка на XSS
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return False, "", "Обнаружена попытка XSS атаки"
        
        # Санитизация с помощью bleach
        sanitized = bleach.clean(text, tags=[], attributes={}, strip=True)
        
        # Дополнительная очистка
        sanitized = html.escape(sanitized, quote=True)
        sanitized = sanitized.replace('\x00', '')  # Удаление null байтов
        sanitized = ' '.join(sanitized.split())  # Удаление лишних пробелов
        
        return True, sanitized, ""
    
    @classmethod
    def validate_path(cls, path: str) -> tuple[bool, str]:
        """Безопасная валидация пути"""
        if not path:
            return False, "Путь не может быть пустым"
        
        if len(path) > cls.MAX_PATH_LENGTH:
            return False, f"Путь не может быть длиннее {cls.MAX_PATH_LENGTH} символов"
        
        # Проверка на path traversal атаки
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return False, "Путь содержит недопустимые символы"
        
        # Проверка на null байты
        if '\x00' in path:
            return False, "Путь содержит недопустимые символы"
        
        # Нормализация пути
        normalized_path = os.path.normpath(path)
        if normalized_path != path:
            return False, "Путь содержит недопустимые символы"
        
        return True, ""
    
    @classmethod
    def validate_json_data(cls, data: Dict[str, Any]) -> tuple[bool, List[str], Dict[str, Any]]:
        """Безопасная валидация JSON данных"""
        errors = []
        sanitized_data = {}
        
        def validate_value(value: Any, path: str = "") -> Any:
            if isinstance(value, str):
                is_valid, sanitized, error = cls.validate_and_sanitize_string(value)
                if not is_valid:
                    errors.append(f"{path}: {error}")
                    return None
                return sanitized
            elif isinstance(value, dict):
                result = {}
                for key, val in value.items():
                    # Валидируем ключ
                    key_valid, key_sanitized, key_error = cls.validate_and_sanitize_string(key, 100)
                    if not key_valid:
                        errors.append(f"{path}.{key}: {key_error}")
                        continue
                    
                    # Валидируем значение
                    validated_val = validate_value(val, f"{path}.{key}")
                    if validated_val is not None:
                        result[key_sanitized] = validated_val
                return result
            elif isinstance(value, list):
                result = []
                for i, item in enumerate(value):
                    validated_item = validate_value(item, f"{path}[{i}]")
                    if validated_item is not None:
                        result.append(validated_item)
                return result
            else:
                return value
        
        sanitized_data = validate_value(data)
        
        return len(errors) == 0, errors, sanitized_data
    
    @classmethod
    def _validate_basic_api_key_checks(cls, api_key: str) -> tuple[bool, str]:
        """Базовые проверки API ключа"""
        if not api_key or len(api_key.strip()) == 0:
            return False, "API ключ не может быть пустым"
        
        if len(api_key) < 10:
            return False, "API ключ слишком короткий"
        
        if len(api_key) > 200:
            return False, "API ключ слишком длинный"
        
        if any(char in api_key for char in ['<', '>', '"', "'", '&', '\x00', ' ']):
            return False, "API ключ содержит недопустимые символы"
        
        return True, ""

    @classmethod
    def _validate_provider_specific_format(cls, api_key: str, provider: str) -> tuple[bool, str]:
        """Проверка формата для конкретного провайдера"""
        # Конфигурация провайдеров
        provider_configs = {
            "openai": {
                "prefix": "sk-",
                "min_length": 20,
                "error_msg": 'OpenAI ключ должен начинаться с "sk-" и быть длиннее 20 символов'
            },
            "anthropic": {
                "prefix": "sk-ant-",
                "min_length": 20,
                "error_msg": 'Anthropic ключ должен начинаться с "sk-ant-" и быть длиннее 20 символов'
            },
            "openrouter": {
                "prefix": "sk-or-",
                "min_length": 20,
                "error_msg": 'OpenRouter ключ должен начинаться с "sk-or-" и быть длиннее 20 символов'
            },
            "groq": {
                "prefix": "",
                "min_length": 20,
                "error_msg": 'Groq ключ должен быть длиннее 20 символов'
            }
        }
        
        provider_lower = provider.lower()
        config = provider_configs.get(provider_lower)
        
        if not config:
            return True, ""  # Неизвестный провайдер - пропускаем проверку
        
        # Проверяем префикс
        if config["prefix"] and not api_key.startswith(config["prefix"]):
            return False, config["error_msg"]
        
        # Проверяем длину
        if len(api_key) < config["min_length"]:
            return False, config["error_msg"]
        
        return True, ""

    @classmethod
    def validate_api_key_format(cls, api_key: str, provider: str) -> tuple[bool, str]:
        """Безопасная валидация API ключа"""
        # Базовые проверки
        is_valid, error_msg = cls._validate_basic_api_key_checks(api_key)
        if not is_valid:
            return False, error_msg
        
        # Проверки для конкретного провайдера
        is_valid, error_msg = cls._validate_provider_specific_format(api_key, provider)
        if not is_valid:
            return False, error_msg
        
        return True, ""

# Глобальный экземпляр безопасного валидатора
secure_validator = SecureInputValidator()