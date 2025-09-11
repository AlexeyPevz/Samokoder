"""
ASVS V12: Критические исправления API Security (P0)
"""
import re
import time
import hashlib
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse
from fastapi import HTTPException, status, Request
from backend.core.common_imports import get_logger

logger = get_logger(__name__)

class APISecurity:
    """Критические исправления API Security"""
    
    def __init__(self):
        self.rate_limit_storage: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Set[str] = set()
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'expression\s*\(',
            r'union\s+select',
            r'drop\s+table',
            r'delete\s+from',
            r'insert\s+into',
            r'update\s+set',
            r'exec\s*\(',
            r'eval\s*\(',
            r'system\s*\(',
            r'cmd\s*\/',
            r'\.\.\/',
            r'\.\.\\',
            r'%00',
            r'%0a',
            r'%0d',
            r'%20',
            r'%2e',
            r'%2f',
            r'%5c',
            r'%7c',
            r'%3c',
            r'%3e',
            r'%22',
            r'%27',
            r'%3b',
            r'%2d',
            r'%2d'
        ]
    
    def validate_api_endpoint(self, endpoint: str, method: str) -> bool:
        """V12.1.1: Валидация API endpoint"""
        if not endpoint or not method:
            return False
        
        # Проверяем формат endpoint
        if not endpoint.startswith('/'):
            return False
        
        # Проверяем наличие опасных символов
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
        if any(char in endpoint for char in dangerous_chars):
            return False
        
        # Проверяем метод HTTP
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        if method.upper() not in valid_methods:
            return False
        
        return True
    
    def validate_request_headers(self, headers: Dict[str, str]) -> List[str]:
        """V12.1.2: Валидация заголовков запроса"""
        issues = []
        
        # Проверяем Content-Type для POST/PUT запросов
        if 'content-type' in headers:
            content_type = headers['content-type'].lower()
            if 'application/json' not in content_type and 'application/x-www-form-urlencoded' not in content_type:
                issues.append("Invalid Content-Type header")
        
        # Проверяем User-Agent
        if 'user-agent' not in headers:
            issues.append("Missing User-Agent header")
        elif len(headers['user-agent']) > 500:
            issues.append("User-Agent header too long")
        
        # Проверяем на подозрительные заголовки
        suspicious_headers = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip']
        for header in suspicious_headers:
            if header in headers and not self._is_valid_ip(headers[header]):
                issues.append(f"Suspicious {header} header")
        
        return issues
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Проверка валидности IP адреса"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_request_body(self, body: str, content_type: str) -> List[str]:
        """V12.1.3: Валидация тела запроса"""
        issues = []
        
        if not body:
            return issues
        
        # Проверяем размер тела запроса
        if len(body) > 10 * 1024 * 1024:  # 10MB
            issues.append("Request body too large")
        
        # Проверяем на подозрительные паттерны
        for pattern in self.suspicious_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                issues.append(f"Suspicious pattern detected: {pattern}")
        
        # Проверяем JSON для application/json
        if 'application/json' in content_type:
            try:
                import json
                json.loads(body)
            except json.JSONDecodeError:
                issues.append("Invalid JSON format")
        
        return issues
    
    def validate_query_parameters(self, params: Dict[str, Any]) -> List[str]:
        """V12.1.4: Валидация параметров запроса"""
        issues = []
        
        for key, value in params.items():
            if isinstance(value, str):
                # Проверяем длину параметра
                if len(value) > 1000:
                    issues.append(f"Parameter {key} too long")
                
                # Проверяем на подозрительные символы
                if any(char in value for char in ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']):
                    issues.append(f"Suspicious characters in parameter {key}")
                
                # Проверяем на подозрительные паттерны
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        issues.append(f"Suspicious pattern in parameter {key}: {pattern}")
        
        return issues
    
    def check_rate_limit(self, client_ip: str, endpoint: str, method: str) -> bool:
        """V12.1.5: Проверка rate limiting"""
        key = f"{client_ip}:{endpoint}:{method}"
        current_time = time.time()
        
        if key not in self.rate_limit_storage:
            self.rate_limit_storage[key] = {
                'requests': [],
                'blocked_until': 0
            }
        
        rate_data = self.rate_limit_storage[key]
        
        # Проверяем, заблокирован ли клиент
        if current_time < rate_data['blocked_until']:
            return False
        
        # Очищаем старые запросы (старше 1 минуты)
        rate_data['requests'] = [
            req_time for req_time in rate_data['requests']
            if current_time - req_time < 60
        ]
        
        # Проверяем лимит (100 запросов в минуту)
        if len(rate_data['requests']) >= 100:
            rate_data['blocked_until'] = current_time + 300  # Блокируем на 5 минут
            logger.warning(f"Rate limit exceeded for {client_ip} on {endpoint}")
            return False
        
        # Добавляем текущий запрос
        rate_data['requests'].append(current_time)
        return True
    
    def detect_brute_force_attack(self, client_ip: str, endpoint: str) -> bool:
        """V12.1.6: Обнаружение brute force атак"""
        key = f"{client_ip}:{endpoint}"
        current_time = time.time()
        
        if key not in self.rate_limit_storage:
            self.rate_limit_storage[key] = {
                'requests': [],
                'blocked_until': 0
            }
        
        rate_data = self.rate_limit_storage[key]
        
        # Очищаем старые запросы (старше 5 минут)
        rate_data['requests'] = [
            req_time for req_time in rate_data['requests']
            if current_time - req_time < 300
        ]
        
        # Проверяем лимит (20 запросов за 5 минут для sensitive endpoints)
        sensitive_endpoints = ['/api/auth/login', '/api/auth/register', '/api/auth/reset-password']
        if endpoint in sensitive_endpoints and len(rate_data['requests']) >= 20:
            rate_data['blocked_until'] = current_time + 900  # Блокируем на 15 минут
            logger.critical(f"Brute force attack detected from {client_ip} on {endpoint}")
            return True
        
        # Добавляем текущий запрос
        rate_data['requests'].append(current_time)
        return False
    
    def validate_api_key(self, api_key: str) -> bool:
        """V12.1.7: Валидация API ключа"""
        if not api_key:
            return False
        
        # Проверяем формат API ключа
        if len(api_key) < 32 or len(api_key) > 128:
            return False
        
        # Проверяем, что ключ содержит только допустимые символы
        if not re.match(r'^[a-zA-Z0-9_-]+$', api_key):
            return False
        
        # В реальном приложении здесь должна быть проверка в базе данных
        return True
    
    def sanitize_api_response(self, response_data: Any) -> Any:
        """V12.1.8: Санитизация ответа API"""
        if isinstance(response_data, str):
            # Удаляем потенциально опасные теги и их содержимое
            sanitized = response_data
            
            # Удаляем script теги и их содержимое
            sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            # Удаляем другие опасные теги
            dangerous_tags = ['iframe', 'object', 'embed', 'link', 'meta', 'style', 'form', 'input', 'button', 'select', 'textarea']
            for tag in dangerous_tags:
                sanitized = re.sub(rf'<{tag}[^>]*>.*?</{tag}>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
                sanitized = re.sub(rf'<{tag}[^>]*/?>', '', sanitized, flags=re.IGNORECASE)
            
            # Удаляем javascript: и другие опасные протоколы
            sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'vbscript:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'data:', '', sanitized, flags=re.IGNORECASE)
            
            # Удаляем expression() и другие опасные CSS функции
            sanitized = re.sub(r'expression\s*\(', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'url\s*\(', '', sanitized, flags=re.IGNORECASE)
            
            # Удаляем on* атрибуты
            sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
            
            # Удаляем оставшиеся опасные символы
            dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, '')
            
            return sanitized
        
        elif isinstance(response_data, dict):
            sanitized = {}
            for key, value in response_data.items():
                sanitized[key] = self.sanitize_api_response(value)
            return sanitized
        
        elif isinstance(response_data, list):
            return [self.sanitize_api_response(item) for item in response_data]
        
        else:
            return response_data
    
    def validate_cors_origin(self, origin: str, allowed_origins: List[str]) -> bool:
        """V12.1.9: Валидация CORS origin"""
        if not origin:
            return False
        
        # Проверяем, что origin в списке разрешенных
        if origin in allowed_origins:
            return True
        
        # Проверяем wildcard поддомены
        for allowed_origin in allowed_origins:
            if allowed_origin.startswith('*.'):
                domain = allowed_origin[2:]
                if origin.endswith(domain):
                    return True
            elif allowed_origin.startswith('https://*.'):
                domain = allowed_origin[9:]  # Убираем 'https://'
                if origin.startswith('https://') and origin[8:].endswith(domain):
                    return True
        
        return False
    
    def detect_sql_injection(self, input_data: str) -> bool:
        """V12.1.10: Обнаружение SQL injection"""
        if not input_data:
            return False
        
        sql_patterns = [
            r'union\s+select',
            r'drop\s+table',
            r'delete\s+from',
            r'insert\s+into',
            r'update\s+set',
            r'select\s+.*\s+from',
            r'where\s+.*\s*=\s*.*',
            r'order\s+by',
            r'group\s+by',
            r'having\s+.*',
            r'exec\s*\(',
            r'execute\s*\(',
            r'sp_',
            r'xp_',
            r'--',
            r'/\*',
            r'\*/',
            r';\s*drop',
            r';\s*delete',
            r';\s*insert',
            r';\s*update',
            r"'\s*or\s*'1'\s*=\s*'1",
            r"'\s*or\s*1\s*=\s*1",
            r"'\s*and\s*'1'\s*=\s*'1",
            r"'\s*and\s*1\s*=\s*1",
            r"'\s*union\s+select",
            r"'\s*;\s*drop",
            r"'\s*;\s*delete",
            r"'\s*;\s*insert",
            r"'\s*;\s*update",
            r"'\s*;\s*exec",
            r"'\s*;\s*execute"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                return True
        
        return False
    
    def detect_xss_attack(self, input_data: str) -> bool:
        """V12.1.11: Обнаружение XSS атак"""
        if not input_data:
            return False
        
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>',
            r'<link[^>]*>.*?</link>',
            r'<meta[^>]*>.*?</meta>',
            r'<style[^>]*>.*?</style>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'expression\s*\(',
            r'url\s*\(',
            r'@import',
            r'behavior\s*:',
            r'-\w+-binding',
            r'on\w+\s*=',
            r'<form[^>]*>',
            r'<input[^>]*>',
            r'<button[^>]*>',
            r'<select[^>]*>',
            r'<textarea[^>]*>'
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                return True
        
        return False
    
    def validate_file_upload(self, filename: str, file_size: int, content_type: str) -> List[str]:
        """V12.1.12: Валидация загрузки файлов"""
        issues = []
        
        if not filename:
            issues.append("Filename is required")
            return issues
        
        # Проверяем размер файла
        if file_size > 10 * 1024 * 1024:  # 10MB
            issues.append("File size too large")
        
        # Проверяем расширение файла
        allowed_extensions = ['.txt', '.md', '.py', '.js', '.json', '.xml', '.csv', '.pdf', '.doc', '.docx']
        file_ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        if file_ext not in allowed_extensions:
            issues.append(f"File extension {file_ext} not allowed")
        
        # Проверяем MIME тип
        allowed_mime_types = {
            'text/plain', 'text/markdown', 'text/csv',
            'application/json', 'application/xml',
            'text/x-python', 'application/javascript',
            'application/pdf', 'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        
        if content_type not in allowed_mime_types:
            issues.append(f"Content type {content_type} not allowed")
        
        # Проверяем имя файла на подозрительные символы
        if any(char in filename for char in ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']):
            issues.append("Filename contains suspicious characters")
        
        return issues
    
    def generate_api_security_report(self, request: Request, response_status: int, 
                                   response_time: float) -> Dict[str, Any]:
        """V12.1.13: Генерация отчета по безопасности API"""
        client_ip = request.client.host if request.client else "unknown"
        
        return {
            "timestamp": time.time(),
            "client_ip": client_ip,
            "endpoint": str(request.url.path),
            "method": request.method,
            "status_code": response_status,
            "response_time": response_time,
            "user_agent": request.headers.get("user-agent", ""),
            "content_type": request.headers.get("content-type", ""),
            "content_length": request.headers.get("content-length", "0"),
            "referer": request.headers.get("referer", ""),
            "security_checks": {
                "rate_limit_passed": self.check_rate_limit(client_ip, str(request.url.path), request.method),
                "brute_force_detected": self.detect_brute_force_attack(client_ip, str(request.url.path)),
                "suspicious_headers": len(self.validate_request_headers(dict(request.headers))) > 0,
                "cors_origin_valid": True  # Должно проверяться в middleware
            }
        }
    
    def block_suspicious_ip(self, ip: str, reason: str) -> None:
        """V12.1.14: Блокировка подозрительного IP"""
        self.blocked_ips.add(ip)
        logger.critical(f"IP {ip} blocked due to: {reason}")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """V12.1.15: Проверка блокировки IP"""
        return ip in self.blocked_ips
    
    def unblock_ip(self, ip: str) -> None:
        """V12.1.16: Разблокировка IP"""
        self.blocked_ips.discard(ip)
        logger.info(f"IP {ip} unblocked")

# Глобальный экземпляр
api_security = APISecurity()