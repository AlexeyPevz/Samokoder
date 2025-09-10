"""
ASVS V2: Тесты безопасности аутентификации
"""
import pytest
import time
from unittest.mock import patch, Mock
from security_patches.asvs_v2_auth_p0_fixes import AuthenticationSecurity

class TestAuthenticationSecurity:
    """Тесты безопасности аутентификации"""
    
    @pytest.fixture
    def auth_security(self):
        """Создать экземпляр AuthenticationSecurity"""
        return AuthenticationSecurity()
    
    def test_password_strength_validation_strong(self, auth_security):
        """V2.1.1: Тест сильного пароля"""
        strong_passwords = [
            "MyStr0ng!Passw0rd",
            "C0mpl3x#P@ssw0rd",
            "S3cur3$P@ssw0rd123"
        ]
        
        for password in strong_passwords:
            assert auth_security.validate_password_strength(password) is True
    
    def test_password_strength_validation_weak(self, auth_security):
        """V2.1.1: Тест слабых паролей"""
        weak_passwords = [
            "password",  # Общий пароль
            "123456",    # Только цифры
            "qwerty",    # Общий пароль
            "Password1", # Нет специальных символов
            "MyPassword!", # Нет цифр
            "1234567890", # Только цифры
            "abcdefgh",   # Только буквы
            "P@ssw0rd",   # Слишком короткий
        ]
        
        for password in weak_passwords:
            assert auth_security.validate_password_strength(password) is False
    
    def test_account_lockout_mechanism(self, auth_security):
        """V2.1.2: Тест механизма блокировки аккаунта"""
        email = "test@example.com"
        
        # Изначально аккаунт не заблокирован
        assert auth_security.check_account_lockout(email) is False
        
        # Записываем неудачные попытки
        for _ in range(5):
            auth_security.record_failed_attempt(email)
        
        # Аккаунт должен быть заблокирован
        assert auth_security.check_account_lockout(email) is True
    
    def test_account_unlock_after_timeout(self, auth_security):
        """V2.1.2: Тест разблокировки аккаунта после таймаута"""
        email = "test@example.com"
        
        # Блокируем аккаунт
        for _ in range(5):
            auth_security.record_failed_attempt(email)
        
        assert auth_security.check_account_lockout(email) is True
        
        # Симулируем прошествие времени
        with patch('time.time', return_value=time.time() + 400):  # 400 секунд
            assert auth_security.check_account_lockout(email) is False
    
    def test_failed_attempts_recording(self, auth_security):
        """V2.1.3: Тест записи неудачных попыток"""
        email = "test@example.com"
        
        # Записываем неудачные попытки
        auth_security.record_failed_attempt(email)
        auth_security.record_failed_attempt(email)
        
        assert auth_security.failed_attempts[email] == 2
    
    def test_reset_failed_attempts_on_success(self, auth_security):
        """V2.1.4: Тест сброса неудачных попыток при успешном входе"""
        email = "test@example.com"
        
        # Записываем неудачные попытки
        auth_security.record_failed_attempt(email)
        auth_security.record_failed_attempt(email)
        
        # Сбрасываем при успешном входе
        auth_security.reset_failed_attempts(email)
        
        assert email not in auth_security.failed_attempts
        assert email not in auth_security.account_lockouts
    
    def test_secure_session_token_generation(self, auth_security):
        """V2.1.5: Тест генерации безопасного токена сессии"""
        token1 = auth_security.generate_secure_session_token()
        token2 = auth_security.generate_secure_session_token()
        
        # Токены должны быть разными
        assert token1 != token2
        
        # Токены должны быть достаточно длинными
        assert len(token1) >= 32
        assert len(token2) >= 32
        
        # Токены должны быть валидными
        assert auth_security.validate_session_token(token1) is True
        assert auth_security.validate_session_token(token2) is True
    
    def test_session_token_validation(self, auth_security):
        """V2.1.6: Тест валидации токена сессии"""
        # Валидный токен
        valid_token = auth_security.generate_secure_session_token()
        assert auth_security.validate_session_token(valid_token) is True
        
        # Невалидные токены
        invalid_tokens = [
            "",  # Пустой токен
            "short",  # Слишком короткий
            "invalid_token_with_special_chars!@#",  # Невалидные символы
            None,  # None
        ]
        
        for token in invalid_tokens:
            if token is not None:
                assert auth_security.validate_session_token(token) is False
    
    def test_password_hashing(self, auth_security):
        """V2.1.7: Тест хеширования пароля"""
        password = "TestPassword123!"
        
        # Хешируем пароль
        hash1, salt1 = auth_security.hash_password_secure(password)
        hash2, salt2 = auth_security.hash_password_secure(password)
        
        # Хеши должны быть разными (из-за разных соли)
        assert hash1 != hash2
        assert salt1 != salt2
        
        # Хеши должны быть достаточно длинными
        assert len(hash1) == 64  # SHA-256 hex
        assert len(salt1) == 32  # 16 bytes hex
    
    def test_password_verification(self, auth_security):
        """V2.1.8: Тест проверки пароля"""
        password = "TestPassword123!"
        
        # Хешируем пароль
        stored_hash, salt = auth_security.hash_password_secure(password)
        
        # Проверяем правильный пароль
        assert auth_security.verify_password(password, stored_hash, salt) is True
        
        # Проверяем неправильный пароль
        assert auth_security.verify_password("WrongPassword", stored_hash, salt) is False
    
    def test_input_sanitization(self, auth_security):
        """V2.1.9: Тест санитизации пользовательского ввода"""
        dangerous_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "test@example.com<script>",
            "normal@example.com",
            "test&user@example.com",
            "test;user@example.com"
        ]
        
        for input_str in dangerous_inputs:
            sanitized = auth_security.sanitize_user_input(input_str)
            
            # Проверяем, что опасные символы удалены
            dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
            for char in dangerous_chars:
                assert char not in sanitized
        
        # Проверяем ограничение длины
        long_input = "a" * 150
        sanitized = auth_security.sanitize_user_input(long_input)
        assert len(sanitized) <= 100
    
    def test_password_history_check(self, auth_security):
        """V2.1.10: Тест проверки истории паролей"""
        email = "test@example.com"
        old_password = "OldPassword123!"
        new_password = "NewPassword123!"
        
        # Создаем историю паролей
        old_hash, old_salt = auth_security.hash_password_secure(old_password)
        password_history = [(old_hash, old_salt)]
        
        # Новый пароль должен быть разрешен
        assert auth_security.check_password_history(email, new_password, password_history) is True
        
        # Старый пароль должен быть запрещен
        assert auth_security.check_password_history(email, old_password, password_history) is False
    
    def test_timing_attack_resistance(self, auth_security):
        """V2.1.11: Тест устойчивости к timing атакам"""
        password = "TestPassword123!"
        stored_hash, salt = auth_security.hash_password_secure(password)
        
        # Измеряем время для правильного пароля
        start_time = time.time()
        auth_security.verify_password(password, stored_hash, salt)
        correct_time = time.time() - start_time
        
        # Измеряем время для неправильного пароля
        start_time = time.time()
        auth_security.verify_password("WrongPassword", stored_hash, salt)
        incorrect_time = time.time() - start_time
        
        # Время должно быть примерно одинаковым (защита от timing атак)
        time_diff = abs(correct_time - incorrect_time)
        assert time_diff < 0.1  # Разница менее 100ms
    
    def test_concurrent_authentication_attempts(self, auth_security):
        """V2.1.12: Тест concurrent попыток аутентификации"""
        import threading
        import time
        
        email = "test@example.com"
        results = []
        
        def attempt_login():
            auth_security.record_failed_attempt(email)
            results.append(auth_security.check_account_lockout(email))
        
        # Создаем несколько потоков
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=attempt_login)
            threads.append(thread)
            thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        # Проверяем, что аккаунт заблокирован
        assert auth_security.check_account_lockout(email) is True