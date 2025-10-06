"""
Централизованная политика паролей - ASVS 2.1.1
Исправление P0-1 и P0-6
"""
from typing import Tuple, List
import logging

logger = logging.getLogger(__name__)

class PasswordPolicy:
    """ASVS 2.1.1 compliant password policy"""
    
    MIN_LENGTH = 12  # ASVS 2.1.1 требует минимум 12 символов
    MAX_LENGTH = 128  # Защита от DoS
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # ASVS 2.1.7: Список общих паролей
    COMMON_PASSWORDS = {
        'password123', 'qwerty123', 'admin123', 
        '123456789abc', 'welcome123', 'letmein123',
        'password1234', 'qwerty1234', 'admin1234',
        'p@ssw0rd123', 'passw0rd123', 'password!23',
        '123456789012', 'abcdefgh123!', 'test12345678'
    }
    
    @classmethod
    def validate(cls, password: str) -> Tuple[bool, List[str]]:
        """
        Валидирует пароль согласно единой политике
        
        Args:
            password: Пароль для проверки
            
        Returns:
            (is_valid, list_of_errors)
        """
        errors = []
        
        if not password:
            errors.append("Password is required")
            return False, errors
        
        # ASVS 2.1.1: Минимальная длина
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Password must be at least {cls.MIN_LENGTH} characters long")
        
        # Защита от DoS: максимальная длина
        if len(password) > cls.MAX_LENGTH:
            errors.append(f"Password must not exceed {cls.MAX_LENGTH} characters")
        
        # ASVS 2.1.1: Требования к сложности
        if cls.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if cls.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if cls.REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if cls.REQUIRE_SPECIAL and not any(c in cls.SPECIAL_CHARS for c in password):
            errors.append(f"Password must contain at least one special character ({cls.SPECIAL_CHARS})")
        
        # ASVS 2.1.7: Проверка на общие пароли
        if password.lower() in cls.COMMON_PASSWORDS:
            errors.append("Password is too common. Please choose a more unique password.")
        
        # Дополнительные проверки паттернов
        if cls._has_sequential_chars(password):
            errors.append("Password contains sequential characters (e.g., '123', 'abc')")
        
        if cls._has_repeated_chars(password):
            errors.append("Password contains too many repeated characters")
        
        return len(errors) == 0, errors
    
    @classmethod
    def _has_sequential_chars(cls, password: str, min_length: int = 3) -> bool:
        """Проверяет на последовательные символы (abc, 123, xyz)"""
        # Проверяем цифры
        for i in range(len(password) - min_length + 1):
            substr = password[i:i + min_length]
            if substr.isdigit() and cls._is_sequential(substr):
                return True
            if substr.isalpha() and cls._is_sequential(substr.lower()):
                return True
        return False
    
    @classmethod
    def _is_sequential(cls, s: str) -> bool:
        """Проверяет, является ли строка последовательной"""
        if len(s) < 2:
            return False
        for i in range(len(s) - 1):
            if ord(s[i + 1]) - ord(s[i]) != 1:
                return False
        return True
    
    @classmethod
    def _has_repeated_chars(cls, password: str, max_repeat: int = 3) -> bool:
        """Проверяет на повторяющиеся символы (aaa, 111)"""
        for i in range(len(password) - max_repeat + 1):
            if len(set(password[i:i + max_repeat])) == 1:
                return True
        return False
    
    @classmethod
    def get_strength_score(cls, password: str) -> int:
        """
        Вычисляет оценку надёжности пароля (0-100)
        
        Returns:
            score: 0-100
        """
        score = 0
        
        # Длина (макс 40 баллов)
        if len(password) >= cls.MIN_LENGTH:
            score += min(40, len(password) * 2)
        
        # Разнообразие символов (макс 40 баллов)
        char_types = 0
        if any(c.isupper() for c in password):
            char_types += 1
            score += 10
        if any(c.islower() for c in password):
            char_types += 1
            score += 10
        if any(c.isdigit() for c in password):
            char_types += 1
            score += 10
        if any(c in cls.SPECIAL_CHARS for c in password):
            char_types += 1
            score += 10
        
        # Уникальность символов (макс 20 баллов)
        unique_ratio = len(set(password)) / len(password) if password else 0
        score += int(unique_ratio * 20)
        
        # Штрафы
        if password.lower() in cls.COMMON_PASSWORDS:
            score -= 50
        if cls._has_sequential_chars(password):
            score -= 20
        if cls._has_repeated_chars(password):
            score -= 15
        
        return max(0, min(100, score))

# Удобная функция для быстрой проверки
def validate_password(password: str) -> bool:
    """Быстрая проверка пароля (только True/False)"""
    is_valid, _ = PasswordPolicy.validate(password)
    return is_valid

def validate_password_with_errors(password: str) -> Tuple[bool, List[str]]:
    """Полная проверка пароля с ошибками"""
    return PasswordPolicy.validate(password)

def get_password_strength(password: str) -> int:
    """Получить оценку надёжности пароля (0-100)"""
    return PasswordPolicy.get_strength_score(password)
