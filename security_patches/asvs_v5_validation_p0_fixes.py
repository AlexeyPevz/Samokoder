"""
ASVS V5: Критические исправления валидации и кодирования (P0)
"""
import re
import html
import json
import base64
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote, unquote
from fastapi import HTTPException, status
from backend.core.common_imports import get_logger

logger = get_logger(__name__)

class ValidationSecurity:
    """Критические исправления валидации и кодирования"""
    
    def __init__(self):
        self.max_input_length = 10000
        self.allowed_file_extensions = {'.txt', '.md', '.py', '.js', '.json', '.xml', '.csv'}
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    def validate_input_length(self, input_data: str, max_length: Optional[int] = None) -> bool:
        """V5.1.1: Валидация длины ввода"""
        if not input_data:
            return True
        
        limit = max_length or self.max_input_length
        return len(input_data) <= limit
    
    def sanitize_html_input(self, input_data: str) -> str:
        """V5.1.2: Санитизация HTML ввода"""
        if not input_data:
            return ""
        
        # Экранируем HTML символы
        sanitized = html.escape(input_data, quote=True)
        
        # Удаляем потенциально опасные теги
        dangerous_patterns = [
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
            r'on\w+\s*='
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized
    
    def validate_email_format(self, email: str) -> bool:
        """V5.1.3: Валидация формата email"""
        if not email:
            return False
        
        # RFC 5322 compliant regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, email) is not None
    
    def validate_url_format(self, url: str) -> bool:
        """V5.1.4: Валидация формата URL"""
        if not url:
            return False
        
        # Проверяем базовый формат URL
        url_pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
        return re.match(url_pattern, url) is not None
    
    def validate_json_input(self, json_data: str) -> bool:
        """V5.1.5: Валидация JSON ввода"""
        if not json_data:
            return False
        
        try:
            json.loads(json_data)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def sanitize_sql_input(self, input_data: str) -> str:
        """V5.1.6: Санитизация SQL ввода"""
        if not input_data:
            return ""
        
        # Удаляем потенциально опасные SQL символы
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_', 'exec", "execute"]
        sanitized = input_data
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized
    
    def validate_file_upload(self, filename: str, file_size: int, content_type: str) -> bool:
        """V5.1.7: Валидация загрузки файла"""
        if not filename or file_size <= 0:
            return False
        
        # Проверяем размер файла
        if file_size > self.max_file_size:
            return False
        
        # Проверяем расширение файла
        file_ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        if file_ext not in self.allowed_file_extensions:
            return False
        
        # Проверяем MIME тип
        allowed_mime_types = {
            'text/plain', 'text/markdown', 'text/csv',
            'application/json', 'application/xml',
            'text/x-python', 'application/javascript'
        }
        
        return content_type in allowed_mime_types
    
    def encode_output_for_html(self, data: str) -> str:
        """V5.1.8: Кодирование вывода для HTML"""
        if not data:
            return ""
        
        return html.escape(data, quote=True)
    
    def encode_output_for_url(self, data: str) -> str:
        """V5.1.9: Кодирование вывода для URL"""
        if not data:
            return ""
        
        return quote(data, safe='')
    
    def encode_output_for_json(self, data: Any) -> str:
        """V5.1.10: Кодирование вывода для JSON"""
        try:
            return json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        except (TypeError, ValueError):
            return json.dumps(str(data), ensure_ascii=False)
    
    def validate_numeric_input(self, value: Union[str, int, float], min_val: Optional[float] = None, 
                             max_val: Optional[float] = None) -> bool:
        """V5.1.11: Валидация числового ввода"""
        try:
            if isinstance(value, str):
                num_value = float(value)
            else:
                num_value = float(value)
            
            if min_val is not None and num_value < min_val:
                return False
            
            if max_val is not None and num_value > max_val:
                return False
            
            return True
        except (ValueError, TypeError):
            return False
    
    def validate_alpha_numeric_input(self, input_data: str, allow_spaces: bool = False) -> bool:
        """V5.1.12: Валидация алфавитно-цифрового ввода"""
        if not input_data:
            return True
        
        pattern = r'^[a-zA-Z0-9' + (r'\s' if allow_spaces else '') + r']+$'
        return re.match(pattern, input_data) is not None
    
    def sanitize_path_input(self, path: str) -> str:
        """V5.1.13: Санитизация пути"""
        if not path:
            return ""
        
        # Удаляем опасные символы
        dangerous_chars = ['..', '~', '$', '`', '|', '&', ';', '(', ')', '<', '>']
        sanitized = path
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Удаляем ведущие слеши
        sanitized = sanitized.lstrip('/')
        
        return sanitized
    
    def validate_base64_input(self, data: str) -> bool:
        """V5.1.14: Валидация Base64 ввода"""
        if not data:
            return False
        
        try:
            # Проверяем, что строка содержит только допустимые символы
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', data):
                return False
            
            # Пытаемся декодировать
            base64.b64decode(data, validate=True)
            return True
        except Exception:
            return False
    
    def prevent_injection_attacks(self, input_data: str) -> str:
        """V5.1.15: Предотвращение injection атак"""
        if not input_data:
            return ""
        
        # Удаляем потенциально опасные паттерны
        injection_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'expression\s*\(',
            r'url\s*\(',
            r'@import',
            r'behavior\s*:',
            r'-\w+-binding',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'<style[^>]*>',
            r'on\w+\s*=',
            r'<form[^>]*>',
            r'<input[^>]*>',
            r'<button[^>]*>',
            r'<select[^>]*>',
            r'<textarea[^>]*>',
            r'<option[^>]*>',
            r'<optgroup[^>]*>',
            r'<fieldset[^>]*>',
            r'<legend[^>]*>',
            r'<label[^>]*>',
            r'<output[^>]*>',
            r'<progress[^>]*>',
            r'<meter[^>]*>',
            r'<details[^>]*>',
            r'<summary[^>]*>',
            r'<dialog[^>]*>',
            r'<menu[^>]*>',
            r'<menuitem[^>]*>',
            r'<command[^>]*>',
            r'<keygen[^>]*>',
            r'<source[^>]*>',
            r'<track[^>]*>',
            r'<video[^>]*>',
            r'<audio[^>]*>',
            r'<canvas[^>]*>',
            r'<svg[^>]*>',
            r'<math[^>]*>',
            r'<table[^>]*>',
            r'<caption[^>]*>',
            r'<col[^>]*>',
            r'<colgroup[^>]*>',
            r'<tbody[^>]*>',
            r'<thead[^>]*>',
            r'<tfoot[^>]*>',
            r'<tr[^>]*>',
            r'<td[^>]*>',
            r'<th[^>]*>',
            r'<dl[^>]*>',
            r'<dt[^>]*>',
            r'<dd[^>]*>',
            r'<ol[^>]*>',
            r'<ul[^>]*>',
            r'<li[^>]*>',
            r'<dir[^>]*>',
            r'<h[1-6][^>]*>',
            r'<p[^>]*>',
            r'<div[^>]*>',
            r'<span[^>]*>',
            r'<a[^>]*>',
            r'<img[^>]*>',
            r'<br[^>]*>',
            r'<hr[^>]*>',
            r'<area[^>]*>',
            r'<map[^>]*>',
            r'<param[^>]*>',
            r'<applet[^>]*>',
            r'<base[^>]*>',
            r'<basefont[^>]*>',
            r'<bgsound[^>]*>',
            r'<blink[^>]*>',
            r'<body[^>]*>',
            r'<center[^>]*>',
            r'<font[^>]*>',
            r'<frame[^>]*>',
            r'<frameset[^>]*>',
            r'<head[^>]*>',
            r'<html[^>]*>',
            r'<isindex[^>]*>',
            r'<listing[^>]*>',
            r'<marquee[^>]*>',
            r'<multicol[^>]*>',
            r'<nextid[^>]*>',
            r'<nobr[^>]*>',
            r'<noembed[^>]*>',
            r'<noframes[^>]*>',
            r'<noscript[^>]*>',
            r'<plaintext[^>]*>',
            r'<spacer[^>]*>',
            r'<strike[^>]*>',
            r'<tt[^>]*>',
            r'<u[^>]*>',
            r'<wbr[^>]*>',
            r'<xmp[^>]*>'
        ]
        
        sanitized = input_data
        for pattern in injection_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized

# Глобальный экземпляр
validation_security = ValidationSecurity()