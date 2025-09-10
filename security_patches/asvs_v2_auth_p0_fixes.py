"""
ASVS V2: Критические исправления аутентификации (P0)
"""
import hashlib
import secrets
import time
from typing import Dict, Optional
from fastapi import HTTPException, status
from backend.core.common_imports import get_logger

logger = get_logger(__name__)

class AuthenticationSecurity:
    """Критические исправления безопасности аутентификации"""
    
    def __init__(self):
        self.failed_attempts: Dict[str, int] = {}
        self.lockout_duration = 300  # 5 минут
        self.max_attempts = 5
        self.account_lockouts: Dict[str, float] = {}
    
    def validate_password_strength(self, password: str) -> bool:
        """V2.1.1: Проверка силы пароля"""
        if len(password) < 12:
            return False
        
        # Проверка на наличие различных типов символов
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        # Проверка на общие пароли
        common_passwords = [
            "password", "123456", "qwerty", "abc123", "password123",
            "admin", "letmein", "welcome", "monkey", "dragon"
        ]
        
        if password.lower() in common_passwords:
            return False
        
        return has_upper and has_lower and has_digit and has_special
    
    def check_account_lockout(self, email: str) -> bool:
        """V2.1.2: Проверка блокировки аккаунта"""
        if email in self.account_lockouts:
            lockout_time = self.account_lockouts[email]
            if time.time() - lockout_time < self.lockout_duration:
                return True
            else:
                # Разблокировать аккаунт
                del self.account_lockouts[email]
                self.failed_attempts[email] = 0
        
        return False
    
    def record_failed_attempt(self, email: str) -> None:
        """V2.1.3: Запись неудачной попытки входа"""
        self.failed_attempts[email] = self.failed_attempts.get(email, 0) + 1
        
        if self.failed_attempts[email] >= self.max_attempts:
            self.account_lockouts[email] = time.time()
            logger.warning(f"Account locked for email: {email}")
    
    def reset_failed_attempts(self, email: str) -> None:
        """V2.1.4: Сброс неудачных попыток при успешном входе"""
        if email in self.failed_attempts:
            del self.failed_attempts[email]
        if email in self.account_lockouts:
            del self.account_lockouts[email]
    
    def generate_secure_session_token(self) -> str:
        """V2.1.5: Генерация безопасного токена сессии"""
        return secrets.token_urlsafe(32)
    
    def validate_session_token(self, token: str) -> bool:
        """V2.1.6: Валидация токена сессии"""
        if not token or len(token) < 32:
            return False
        
        # Проверка формата токена
        try:
            # Декодирование base64url
            import base64
            base64.urlsafe_b64decode(token + "==")
            return True
        except Exception:
            return False
    
    def hash_password_secure(self, password: str, salt: Optional[str] = None) -> tuple[str, str]:
        """V2.1.7: Безопасное хеширование пароля"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Используем PBKDF2 с SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100,000 итераций
        )
        
        return password_hash.hex(), salt
    
    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """V2.1.8: Проверка пароля"""
        password_hash, _ = self.hash_password_secure(password, salt)
        return secrets.compare_digest(password_hash, stored_hash)
    
    def sanitize_user_input(self, input_str: str) -> str:
        """V2.1.9: Санитизация пользовательского ввода"""
        if not input_str:
            return ""
        
        # Удаление потенциально опасных символов
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
        sanitized = input_str
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Ограничение длины
        return sanitized[:100]
    
    def check_password_history(self, email: str, new_password: str, password_history: list) -> bool:
        """V2.1.10: Проверка истории паролей"""
        # Проверяем, не использовался ли этот пароль в последних 5 паролях
        for old_hash, old_salt in password_history[-5:]:
            if self.verify_password(new_password, old_hash, old_salt):
                return False
        
        return True

# Глобальный экземпляр
auth_security = AuthenticationSecurity()