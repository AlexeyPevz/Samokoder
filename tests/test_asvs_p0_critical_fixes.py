"""
ASVS P0 Critical Vulnerabilities Tests
Тесты для критических исправлений безопасности
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# P0-1, P0-6: Password Policy Tests
from backend.security.password_policy import PasswordPolicy, validate_password, get_password_strength

class TestPasswordPolicy:
    """ASVS 2.1.1: Тесты политики паролей"""
    
    def test_minimum_length_12_chars(self):
        """P0-1: Пароль должен быть минимум 12 символов"""
        # Слишком короткие
        assert not validate_password("Short1!")  # 7
        assert not validate_password("Medium12!")  # 9
        assert not validate_password("Almost123!")  # 10
        
        # Правильная длина
        assert validate_password("ValidPass123!")  # 13 ✅
        assert validate_password("LongPassword1!")  # 14 ✅
    
    def test_maximum_length_dos_protection(self):
        """P0-1: Защита от DoS через длинные пароли"""
        long_pass = "A" * 129 + "a1!"
        is_valid, errors = PasswordPolicy.validate(long_pass)
        assert not is_valid
        assert any("exceed" in err for err in errors)
        
        # Приемлемая длина
        acceptable = "A" * 120 + "a1!"
        assert validate_password(acceptable)
    
    def test_complexity_requirements(self):
        """P0-1: Требования к сложности пароля"""
        test_cases = [
            ("alllowercase123!", False, "no uppercase"),
            ("ALLUPPERCASE123!", False, "no lowercase"),
            ("NoDigitsHere!!", False, "no digits"),
            ("NoSpecial12345", False, "no special chars"),
            ("ValidPassword123!", True, "all requirements met")
        ]
        
        for password, expected, description in test_cases:
            result = validate_password(password)
            assert result == expected, f"Failed for {description}: {password}"
    
    def test_common_passwords_rejected(self):
        """P0-1: ASVS 2.1.7 - Отклонение общих паролей"""
        common_passwords = [
            "Password123!",
            "Qwerty123!",
            "Admin123!",
            "Welcome123!",
            "Letmein123!"
        ]
        
        for password in common_passwords:
            is_valid, errors = PasswordPolicy.validate(password)
            assert not is_valid
            assert any("common" in err.lower() for err in errors)
    
    def test_sequential_characters_rejected(self):
        """P0-1: Отклонение последовательных символов"""
        passwords_with_sequential = [
            "Abc123456789!",  # 123456789
            "Abcdefgh123!",   # abcdefgh
            "Xyz12345678!"    # xyz, 12345678
        ]
        
        for password in passwords_with_sequential:
            is_valid, errors = PasswordPolicy.validate(password)
            assert not is_valid
            assert any("sequential" in err.lower() for err in errors)
    
    def test_repeated_characters_rejected(self):
        """P0-1: Отклонение повторяющихся символов"""
        passwords_with_repeats = [
            "Aaa123456789!",  # aaa
            "Abc111111111!",  # 111111111
            "Abcddddddddd1!"  # ddddddddd
        ]
        
        for password in passwords_with_repeats:
            is_valid, errors = PasswordPolicy.validate(password)
            assert not is_valid
            assert any("repeated" in err.lower() for err in errors)
    
    def test_password_strength_score(self):
        """P0-1: Оценка надёжности пароля"""
        weak = "Password123!"  # Общий пароль
        medium = "MyP@ssw0rd99"  # 12 chars, но короткий
        strong = "C0mpl3x!P@ssw0rd#2024"  # Длинный и сложный
        
        assert get_password_strength(weak) < 50
        assert 50 <= get_password_strength(medium) < 80
        assert get_password_strength(strong) >= 80
    
    def test_consistency_with_auth_dependencies(self):
        """P0-6: Согласованность валидации между модулями"""
        from backend.auth.dependencies import secure_password_validation
        
        test_passwords = [
            "Short1!",
            "ValidPass123!",
            "Password123!",
            "NoSpecial123"
        ]
        
        for password in test_passwords:
            policy_result = validate_password(password)
            auth_result = secure_password_validation(password)
            
            assert policy_result == auth_result, \
                f"Inconsistent validation for {password}"


# P0-2: Account Lockout Tests
from backend.security.account_lockout import AccountLockoutManager, lockout_manager

class TestAccountLockout:
    """ASVS 2.2.1: Тесты блокировки аккаунтов"""
    
    @pytest.mark.asyncio
    async def test_lockout_after_5_attempts(self):
        """P0-2: ASVS 2.2.1 - Блокировка после 5 неудачных попыток"""
        manager = AccountLockoutManager()
        email = "test@example.com"
        
        # Первые 4 попытки
        for i in range(4):
            is_locked, attempts_left, _ = await manager.record_failed_attempt(email)
            assert not is_locked
            assert attempts_left == 5 - (i + 1)
        
        # 5-я попытка - блокировка
        is_locked, attempts_left, unlock_time = await manager.record_failed_attempt(email)
        assert is_locked
        assert attempts_left == 0
        assert unlock_time > datetime.now()
    
    @pytest.mark.asyncio
    async def test_lockout_duration_30_minutes(self):
        """P0-2: ASVS 2.2.1 - Блокировка на 30 минут"""
        manager = AccountLockoutManager()
        email = "test@example.com"
        
        # Блокируем аккаунт
        for _ in range(5):
            await manager.record_failed_attempt(email)
        
        is_locked, unlock_time = await manager.is_locked(email)
        assert is_locked
        
        # Проверяем, что время разблокировки примерно через 30 минут
        expected_unlock = datetime.now() + timedelta(minutes=30)
        time_diff = abs((unlock_time - expected_unlock).total_seconds())
        assert time_diff < 5  # Погрешность 5 секунд
    
    @pytest.mark.asyncio
    async def test_auto_unlock_after_timeout(self):
        """P0-2: Автоматическая разблокировка после истечения времени"""
        manager = AccountLockoutManager()
        manager.lockout_duration = timedelta(seconds=1)  # Для теста
        
        email = "test@example.com"
        
        # Блокируем
        for _ in range(5):
            await manager.record_failed_attempt(email)
        
        is_locked, _ = await manager.is_locked(email)
        assert is_locked
        
        # Ждём разблокировки
        await asyncio.sleep(2)
        
        is_locked, _ = await manager.is_locked(email)
        assert not is_locked
    
    @pytest.mark.asyncio
    async def test_successful_login_resets_counter(self):
        """P0-2: Успешный вход сбрасывает счётчик"""
        manager = AccountLockoutManager()
        email = "test@example.com"
        
        # 3 неудачные попытки
        for _ in range(3):
            await manager.record_failed_attempt(email)
        
        # Успешный вход
        await manager.reset_attempts(email)
        
        # Проверяем, что счётчик сброшен
        is_locked, attempts_left, _ = await manager.record_failed_attempt(email)
        assert not is_locked
        assert attempts_left == 4  # Снова 5 попыток
    
    @pytest.mark.asyncio
    async def test_concurrent_lockout_checks(self):
        """P0-2: Thread-safety при конкурентных проверках"""
        manager = AccountLockoutManager()
        email = "test@example.com"
        
        async def attempt():
            return await manager.record_failed_attempt(email)
        
        # 10 конкурентных попыток
        results = await asyncio.gather(*[attempt() for _ in range(10)])
        
        # Должно быть заблокировано после 5-й
        locked_count = sum(1 for is_locked, _, _ in results if is_locked)
        assert locked_count >= 5
    
    @pytest.mark.asyncio
    async def test_lockout_info_retrieval(self):
        """P0-2: Получение информации о блокировке"""
        manager = AccountLockoutManager()
        email = "test@example.com"
        
        # 3 попытки
        for _ in range(3):
            await manager.record_failed_attempt(email)
        
        info = await manager.get_lockout_info(email)
        
        assert info["failed_attempts"] == 3
        assert info["attempts_left"] == 2
        assert not info["is_locked"]
        assert info["unlock_time"] is None


# P0-3, P0-4: MFA Tests
from backend.security.mfa_storage import (
    get_mfa_secret, save_mfa_secret, delete_mfa_secret,
    get_backup_codes, generate_backup_codes, use_backup_code
)

class TestMFAStorage:
    """ASVS 2.8.1: Тесты хранения MFA"""
    
    @pytest.mark.asyncio
    async def test_save_and_retrieve_mfa_secret(self):
        """P0-4: Сохранение и получение MFA секрета"""
        user_id = "test_user_mfa_1"
        secret = "JBSWY3DPEHPK3PXP"
        
        # Сохраняем
        success = await save_mfa_secret(user_id, secret)
        assert success
        
        # Получаем
        retrieved = await get_mfa_secret(user_id)
        assert retrieved == secret
    
    @pytest.mark.asyncio
    async def test_mfa_secret_encryption(self):
        """P0-4: ASVS 2.8.1 - Секреты хранятся зашифрованными"""
        # Проверяем, что в БД хранится зашифрованное значение
        # (не равное оригинальному секрету)
        user_id = "test_user_mfa_2"
        secret = "JBSWY3DPEHPK3PXP"
        
        await save_mfa_secret(user_id, secret)
        
        # TODO: Проверить в БД, что stored_value != secret
        # (требуется прямой доступ к БД для проверки)
    
    @pytest.mark.asyncio
    async def test_delete_mfa_secret(self):
        """P0-4: ASVS 2.8.5 - Возможность отключения MFA"""
        user_id = "test_user_mfa_3"
        secret = "JBSWY3DPEHPK3PXP"
        
        # Сохраняем
        await save_mfa_secret(user_id, secret)
        
        # Удаляем
        success = await delete_mfa_secret(user_id)
        assert success
        
        # Проверяем, что удалено
        retrieved = await get_mfa_secret(user_id)
        assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_mfa_secret(self):
        """P0-4: Получение несуществующего секрета возвращает None"""
        secret = await get_mfa_secret("nonexistent_user_999")
        assert secret is None
    
    @pytest.mark.asyncio
    async def test_generate_backup_codes(self):
        """P0-4: ASVS 2.8.2 - Генерация backup кодов"""
        user_id = "test_user_mfa_4"
        
        codes = await generate_backup_codes(user_id, count=10)
        
        assert len(codes) == 10
        assert all(len(code) == 8 for code in codes)
        assert all(code.isdigit() for code in codes)
        assert len(set(codes)) == 10  # Все уникальные
    
    @pytest.mark.asyncio
    async def test_use_backup_code(self):
        """P0-4: ASVS 2.8.2 - Использование backup кода"""
        user_id = "test_user_mfa_5"
        
        # Генерируем коды
        codes = await generate_backup_codes(user_id, count=5)
        test_code = codes[0]
        
        # Используем код
        valid = await use_backup_code(user_id, test_code)
        assert valid
        
        # Повторное использование должно провалиться
        valid_again = await use_backup_code(user_id, test_code)
        assert not valid_again
    
    @pytest.mark.asyncio
    async def test_invalid_backup_code(self):
        """P0-4: Неверный backup код отклоняется"""
        user_id = "test_user_mfa_6"
        
        await generate_backup_codes(user_id, count=5)
        
        # Используем неверный код
        valid = await use_backup_code(user_id, "99999999")
        assert not valid


# P0-3: MFA Bypass Tests
class TestMFANoBypass:
    """ASVS 2.8.1: Тесты отсутствия bypass в MFA"""
    
    @pytest.mark.asyncio
    async def test_mfa_fails_without_pyotp(self):
        """P0-3: MFA должна отказывать при отсутствии pyotp"""
        # Этот тест проверяет, что fallback mode удалён
        # и MFA не принимает любой 6-значный код
        
        # Импортируем MFA endpoint
        from backend.api.mfa import verify_mfa
        from fastapi import HTTPException
        
        # Мокаем отсутствие pyotp
        with patch.dict('sys.modules', {'pyotp': None}):
            mock_request = MagicMock(code="123456")
            mock_user = {"id": "test_user"}
            
            # Должно выбросить HTTPException вместо принятия кода
            with pytest.raises(HTTPException) as exc_info:
                await verify_mfa(mock_request, mock_user)
            
            assert exc_info.value.status_code in [500, 503]
    
    def test_mfa_dev_mode_removed(self):
        """P0-3: Dev mode должен быть удалён из кода"""
        # Проверяем, что в коде mfa.py нет dev mode fallback
        import inspect
        from backend.api import mfa
        
        source = inspect.getsource(mfa.verify_mfa)
        
        # Не должно быть строк с dev mode
        assert "dev mode" not in source.lower()
        assert "len(request.code) == 6 and request.code.isdigit()" not in source


# P0-5: Session Race Condition Tests
from backend.security.session_manager import SecureSessionManager, SessionState

class TestSessionRaceCondition:
    """ASVS 3.2.1: Тесты атомарности операций с сессиями"""
    
    @pytest.mark.asyncio
    async def test_concurrent_session_creation_no_race(self):
        """P0-5: ASVS 3.2.1 - Атомарность создания сессий"""
        manager = SecureSessionManager(
            secret_key="test_secret_key_12345",
            session_timeout=3600
        )
        manager.max_sessions_per_user = 5
        
        user_id = "test_user"
        
        async def create_session_task():
            return await manager.create_session(
                user_id=user_id,
                ip_address="127.0.0.1",
                user_agent="Test Agent"
            )
        
        # Создаём 10 сессий конкурентно
        tasks = [create_session_task() for _ in range(10)]
        session_ids = await asyncio.gather(*tasks)
        
        # Проверяем, что все session_ids уникальные
        assert len(session_ids) == len(set(session_ids))
        
        # Проверяем, что только 5 активных сессий (лимит)
        active_sessions = [
            sid for sid in session_ids
            if sid in manager.sessions and 
            manager.sessions[sid].state == SessionState.ACTIVE
        ]
        
        assert len(active_sessions) <= 5
        assert len(manager.user_sessions[user_id]) <= 5
    
    @pytest.mark.asyncio
    async def test_session_cleanup_atomic(self):
        """P0-5: ASVS 3.2.1 - Атомарность очистки сессий"""
        manager = SecureSessionManager(
            secret_key="test_secret_key_12345",
            session_timeout=1  # 1 секунда для теста
        )
        
        # Создаём сессию
        session_id = await manager.create_session(
            user_id="test_user",
            ip_address="127.0.0.1",
            user_agent="Test"
        )
        
        # Ждём истечения
        await asyncio.sleep(2)
        
        # Очищаем истекшие сессии
        cleaned = manager.cleanup_expired_sessions()
        
        assert cleaned == 1
        assert session_id not in manager.sessions or \
               manager.sessions[session_id].state == SessionState.REVOKED
    
    @pytest.mark.asyncio
    async def test_session_revocation_thread_safe(self):
        """P0-5: Thread-safety при отзыве сессий"""
        manager = SecureSessionManager(
            secret_key="test_secret_key_12345",
            session_timeout=3600
        )
        
        user_id = "test_user"
        
        # Создаём несколько сессий
        session_ids = []
        for _ in range(5):
            sid = await manager.create_session(
                user_id=user_id,
                ip_address="127.0.0.1",
                user_agent="Test"
            )
            session_ids.append(sid)
        
        # Конкурентно отзываем все сессии
        async def revoke(sid):
            return manager.revoke_session(sid)
        
        results = await asyncio.gather(*[revoke(sid) for sid in session_ids])
        
        # Все должны быть успешно отозваны
        assert all(results)
        assert len(manager.user_sessions.get(user_id, set())) == 0


# Integration Tests
class TestP0IntegrationFixes:
    """Интеграционные тесты исправлений P0"""
    
    @pytest.mark.asyncio
    async def test_full_auth_flow_with_lockout(self):
        """P0 Integration: Полный flow аутентификации с блокировкой"""
        from backend.security.account_lockout import lockout_manager
        
        email = "integration@test.com"
        
        # Проверяем, что не заблокирован
        is_locked, _ = await lockout_manager.is_locked(email)
        assert not is_locked
        
        # 5 неудачных попыток
        for _ in range(5):
            await lockout_manager.record_failed_attempt(email)
        
        # Должен быть заблокирован
        is_locked, unlock_time = await lockout_manager.is_locked(email)
        assert is_locked
        assert unlock_time is not None
        
        # Даже с правильным паролем не должен войти (проверка в endpoint)
    
    @pytest.mark.asyncio
    async def test_mfa_setup_and_verify_flow(self):
        """P0 Integration: Полный flow MFA"""
        user_id = "integration_user_mfa"
        
        # 1. Генерируем секрет
        import pyotp
        secret = pyotp.random_base32()
        
        # 2. Сохраняем
        success = await save_mfa_secret(user_id, secret)
        assert success
        
        # 3. Генерируем backup коды
        codes = await generate_backup_codes(user_id, count=10)
        assert len(codes) == 10
        
        # 4. Получаем секрет
        retrieved_secret = await get_mfa_secret(user_id)
        assert retrieved_secret == secret
        
        # 5. Используем backup код
        valid = await use_backup_code(user_id, codes[0])
        assert valid
        
        # 6. Отключаем MFA
        success = await delete_mfa_secret(user_id)
        assert success
        
        # 7. Секрет должен быть удалён
        retrieved = await get_mfa_secret(user_id)
        assert retrieved is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
