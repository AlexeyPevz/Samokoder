"""
ASVS V3: Тесты безопасности управления сессиями - рефакторированная версия
Разделены на специализированные классы для лучшей организации
"""

import pytest
import time
from unittest.mock import patch
from security_patches.asvs_v3_sessions_p0_fixes import SessionSecurity

class BaseSessionTest:
    """Базовый класс для тестов управления сессиями"""
    
    @pytest.fixture
    def session_security(self):
        """Создать экземпляр SessionSecurity"""
        return SessionSecurity()

class TestSessionIDGeneration(BaseSessionTest):
    """Тесты генерации ID сессий"""
    
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
        safe_pattern = re.compile(r'^[a-zA-Z0-9_-]+$')
        assert safe_pattern.match(session_id1) is not None
        assert safe_pattern.match(session_id2) is not None

class TestSessionManagement(BaseSessionTest):
    """Тесты управления сессиями"""
    
    def test_session_creation(self, session_security):
        """V3.1.2: Тест создания сессии"""
        user_id = "user123"
        session_data = {"role": "user", "permissions": ["read"]}
        
        session_id = session_security.create_session(user_id, session_data)
        
        assert session_id is not None
        assert len(session_id) >= 32
        
        # Проверяем, что сессия создана
        session = session_security.get_session(session_id)
        assert session is not None
        assert session["user_id"] == user_id
        assert session["data"] == session_data

    def test_session_validation(self, session_security):
        """V3.1.2: Тест валидации сессии"""
        user_id = "user123"
        session_data = {"role": "user"}
        
        # Создаем сессию
        session_id = session_security.create_session(user_id, session_data)
        
        # Валидируем сессию
        is_valid = session_security.validate_session(session_id)
        assert is_valid is True
        
        # Проверяем несуществующую сессию
        is_valid = session_security.validate_session("invalid_session_id")
        assert is_valid is False

class TestSessionSecurity(BaseSessionTest):
    """Основные тесты безопасности сессий"""
    
    def test_session_security_initialization(self, session_security):
        """V3.1.3: Тест инициализации безопасности сессий"""
        assert hasattr(session_security, 'sessions')
        assert hasattr(session_security, 'session_timeout')
        assert isinstance(session_security.sessions, dict)
        assert session_security.session_timeout > 0