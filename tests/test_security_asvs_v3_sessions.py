"""
ASVS V3: Тесты безопасности управления сессиями
"""
import pytest
import time
from unittest.mock import patch
from security_patches.asvs_v3_sessions_p0_fixes import SessionSecurity

class TestSessionSecurity:
    """Тесты безопасности управления сессиями"""
    
    @pytest.fixture
    def session_security(self):
        """Создать экземпляр SessionSecurity"""
        return SessionSecurity()
    
    def test_secure_session_id_generation(self, session_security):
        """V3.1.1: Тест генерации безопасного ID сессии"""
        session_id1 = session_security.generate_secure_session_id()
        session_id2 = session_security.generate_secure_session_id()
        
        # ID должны быть разными
        assert session_id1 != session_id2
        
        # ID должны быть достаточно длинными
        assert len(session_id1) >= 32
        assert len(session_id2) >= 32
        
        # ID должны содержать только безопасные символы
        import re
        assert re.match(r'^[A-Za-z0-9_-]+$', session_id1)
        assert re.match(r'^[A-Za-z0-9_-]+$', session_id2)
    
    def test_session_creation(self, session_security):
        """V3.1.2: Тест создания сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Проверяем, что сессия создана
        assert session_id in session_security.active_sessions
        
        session = session_security.active_sessions[session_id]
        assert session['user_id'] == user_id
        assert session['user_agent'] == user_agent
        assert session['ip_address'] == ip_address
        assert session['is_active'] is True
        assert 'csrf_token' in session
    
    def test_session_validation_success(self, session_security):
        """V3.1.3: Тест успешной валидации сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Валидация должна пройти успешно
        assert session_security.validate_session(session_id, user_agent, ip_address) is True
    
    def test_session_validation_failure(self, session_security):
        """V3.1.3: Тест неудачной валидации сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Неправильный User-Agent
        assert session_security.validate_session(session_id, "Different User Agent", ip_address) is False
        
        # Неправильный IP
        assert session_security.validate_session(session_id, user_agent, "10.0.0.1") is False
        
        # Несуществующая сессия
        assert session_security.validate_session("invalid_session_id", user_agent, ip_address) is False
    
    def test_session_timeout(self, session_security):
        """V3.1.3: Тест таймаута сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Симулируем истечение времени
        with patch('time.time', return_value=time.time() + 2000):  # 2000 секунд
            assert session_security.validate_session(session_id, user_agent, ip_address) is False
    
    def test_session_invalidation(self, session_security):
        """V3.1.4: Тест инвалидации сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Инвалидируем сессию
        assert session_security.invalidate_session(session_id) is True
        
        # Сессия должна быть удалена
        assert session_id not in session_security.active_sessions
        
        # Повторная инвалидация должна вернуть False
        assert session_security.invalidate_session(session_id) is False
    
    def test_user_sessions_invalidation(self, session_security):
        """V3.1.5: Тест инвалидации всех сессий пользователя"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        # Создаем несколько сессий для одного пользователя
        session_id1 = session_security.create_session(user_id, user_agent, ip_address)
        session_id2 = session_security.create_session(user_id, user_agent, ip_address)
        
        # Инвалидируем все сессии пользователя
        invalidated_count = session_security.invalidate_user_sessions(user_id)
        
        assert invalidated_count == 2
        assert session_id1 not in session_security.active_sessions
        assert session_id2 not in session_security.active_sessions
    
    def test_csrf_token_generation(self, session_security):
        """V3.1.6: Тест генерации CSRF токена"""
        token1 = session_security.generate_csrf_token()
        token2 = session_security.generate_csrf_token()
        
        # Токены должны быть разными
        assert token1 != token2
        
        # Токены должны быть достаточно длинными
        assert len(token1) >= 32
        assert len(token2) >= 32
    
    def test_csrf_token_validation(self, session_security):
        """V3.1.7: Тест валидации CSRF токена"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        session = session_security.active_sessions[session_id]
        csrf_token = session['csrf_token']
        
        # Правильный токен
        assert session_security.validate_csrf_token(session_id, csrf_token) is True
        
        # Неправильный токен
        assert session_security.validate_csrf_token(session_id, "wrong_token") is False
        
        # Несуществующая сессия
        assert session_security.validate_csrf_token("invalid_session", csrf_token) is False
    
    def test_session_id_rotation(self, session_security):
        """V3.1.8: Тест ротации ID сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        old_session_id = session_security.create_session(user_id, user_agent, ip_address)
        old_csrf_token = session_security.active_sessions[old_session_id]['csrf_token']
        
        # Ротируем ID сессии
        new_session_id = session_security.rotate_session_id(old_session_id)
        
        assert new_session_id is not None
        assert new_session_id != old_session_id
        assert old_session_id not in session_security.active_sessions
        assert new_session_id in session_security.active_sessions
        
        # CSRF токен должен быть обновлен
        new_csrf_token = session_security.active_sessions[new_session_id]['csrf_token']
        assert new_csrf_token != old_csrf_token
    
    def test_expired_sessions_cleanup(self, session_security):
        """V3.1.9: Тест очистки истекших сессий"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        # Создаем сессию
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Симулируем истечение времени
        with patch('time.time', return_value=time.time() + 2000):  # 2000 секунд
            cleaned_count = session_security.cleanup_expired_sessions()
            
            assert cleaned_count == 1
            assert session_id not in session_security.active_sessions
    
    def test_session_info_retrieval(self, session_security):
        """V3.1.10: Тест получения информации о сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Получаем информацию о сессии
        session_info = session_security.get_session_info(session_id)
        
        assert session_info is not None
        assert session_info['user_id'] == user_id
        assert session_info['user_agent'] == user_agent
        assert session_info['ip_address'] == ip_address
        
        # CSRF токен не должен быть в информации
        assert 'csrf_token' not in session_info
    
    def test_session_attributes(self, session_security):
        """V3.1.11-12: Тест атрибутов сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Устанавливаем атрибут
        assert session_security.set_session_attribute(session_id, 'theme', 'dark') is True
        
        # Получаем атрибут
        assert session_security.get_session_attribute(session_id, 'theme') == 'dark'
        
        # Пытаемся установить запрещенный атрибут
        assert session_security.set_session_attribute(session_id, 'user_id', 'hacker') is False
        
        # Получаем несуществующий атрибут
        assert session_security.get_session_attribute(session_id, 'nonexistent') is None
    
    def test_session_timeout_enforcement(self, session_security):
        """V3.1.13: Тест принудительного завершения сессии по таймауту"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Симулируем истечение времени
        with patch('time.time', return_value=time.time() + 2000):  # 2000 секунд
            assert session_security.enforce_session_timeout(session_id) is True
            assert session_id not in session_security.active_sessions
    
    def test_session_anomaly_detection(self, session_security):
        """V3.1.14: Тест обнаружения аномалий в сессии"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        session_id = session_security.create_session(user_id, user_agent, ip_address)
        
        # Нормальная активность
        anomalies = session_security.detect_session_anomalies(session_id, user_agent, ip_address)
        assert anomalies['user_agent_changed'] is False
        assert anomalies['ip_address_changed'] is False
        assert anomalies['session_expired'] is False
        
        # Изменение User-Agent
        anomalies = session_security.detect_session_anomalies(session_id, "Different Agent", ip_address)
        assert anomalies['user_agent_changed'] is True
        
        # Изменение IP адреса
        anomalies = session_security.detect_session_anomalies(session_id, user_agent, "10.0.0.1")
        assert anomalies['ip_address_changed'] is True
    
    def test_max_sessions_per_user(self, session_security):
        """V3.1.15: Тест ограничения количества сессий на пользователя"""
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        # Создаем максимальное количество сессий
        session_ids = []
        for i in range(session_security.max_sessions_per_user + 2):
            session_id = session_security.create_session(user_id, user_agent, ip_address)
            session_ids.append(session_id)
        
        # Количество активных сессий не должно превышать лимит
        active_count = session_security.get_active_sessions_count(user_id)
        assert active_count <= session_security.max_sessions_per_user
        
        # Старые сессии должны быть удалены
        assert len(session_security.active_sessions) <= session_security.max_sessions_per_user
    
    def test_concurrent_session_operations(self, session_security):
        """V3.1.16: Тест concurrent операций с сессиями"""
        import threading
        import time
        
        user_id = "user123"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ip_address = "192.168.1.1"
        
        results = []
        
        def create_and_validate_session():
            session_id = session_security.create_session(user_id, user_agent, ip_address)
            is_valid = session_security.validate_session(session_id, user_agent, ip_address)
            results.append((session_id, is_valid))
        
        # Создаем несколько потоков
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=create_and_validate_session)
            threads.append(thread)
            thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        # Проверяем результаты
        assert len(results) == 10
        for session_id, is_valid in results:
            assert is_valid is True
            assert session_id in session_security.active_sessions