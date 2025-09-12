"""
Комплексные тесты для SecureRateLimiter (34% покрытие)
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import time
import hashlib
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

from backend.middleware.secure_rate_limiter import SecureRateLimiter


class TestSecureRateLimiter:
    """Тесты для SecureRateLimiter"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.limiter = SecureRateLimiter()

    def test_init(self):
        """Тест инициализации SecureRateLimiter"""
        limiter = SecureRateLimiter()
        assert hasattr(limiter, '_storage')
        assert hasattr(limiter, 'auth_limits')
        assert hasattr(limiter, 'general_limits')
        assert isinstance(limiter._storage, dict)
        assert 'login' in limiter.auth_limits
        assert 'api' in limiter.general_limits

    def test_init_limits(self):
        """Тест инициализации лимитов"""
        assert self.limiter.auth_limits['login']['attempts'] == 3
        assert self.limiter.auth_limits['login']['window'] == 900
        assert self.limiter.auth_limits['register']['attempts'] == 5
        assert self.limiter.auth_limits['register']['window'] == 3600
        assert self.limiter.general_limits['api']['attempts'] == 100
        assert self.limiter.general_limits['api']['window'] == 3600

    def test_get_client_identifier(self):
        """Тест получения идентификатора клиента"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        
        # Act
        identifier = self.limiter._get_client_identifier(mock_request)
        
        # Assert
        assert isinstance(identifier, str)
        assert len(identifier) == 16
        # Проверяем что результат детерминистичен
        identifier2 = self.limiter._get_client_identifier(mock_request)
        assert identifier == identifier2

    def test_get_client_identifier_no_client(self):
        """Тест получения идентификатора клиента без client"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client = None
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        
        # Act
        identifier = self.limiter._get_client_identifier(mock_request)
        
        # Assert
        assert isinstance(identifier, str)
        assert len(identifier) == 16

    def test_get_client_identifier_no_user_agent(self):
        """Тест получения идентификатора клиента без user-agent"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {}
        
        # Act
        identifier = self.limiter._get_client_identifier(mock_request)
        
        # Assert
        assert isinstance(identifier, str)
        assert len(identifier) == 16

    def test_get_rate_limit_key(self):
        """Тест создания ключа для rate limiting"""
        # Arrange
        identifier = "test_client_123"
        endpoint = "login"
        
        # Act
        key = self.limiter._get_rate_limit_key(identifier, endpoint)
        
        # Assert
        assert key == "rate_limit:test_client_123:login"

    def test_is_allowed_new_client(self):
        """Тест проверки разрешения для нового клиента"""
        # Arrange
        identifier = "new_client"
        endpoint = "login"
        
        # Act
        result = self.limiter._is_allowed(identifier, endpoint)
        
        # Assert
        assert result is True

    def test_is_allowed_within_limits(self):
        """Тест проверки разрешения в пределах лимитов"""
        # Arrange
        identifier = "test_client"
        endpoint = "login"
        current_time = time.time()
        
        # Симулируем 2 попытки (в пределах лимита 3)
        self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"] = {
            "attempts": 2,
            "window_start": current_time
        }
        
        # Act
        result = self.limiter._is_allowed(identifier, endpoint)
        
        # Assert
        assert result is True

    def test_is_allowed_exceeds_limits(self):
        """Тест проверки разрешения при превышении лимитов"""
        # Arrange
        identifier = "test_client"
        endpoint = "login"
        current_time = time.time()
        
        # Симулируем 3 попытки (превышение лимита 3)
        self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"] = {
            "attempts": 3,
            "window_start": current_time
        }
        
        # Act
        result = self.limiter._is_allowed(identifier, endpoint)
        
        # Assert
        assert result is False

    def test_is_allowed_window_expired(self):
        """Тест проверки разрешения после истечения окна"""
        # Arrange
        identifier = "test_client"
        endpoint = "login"
        old_time = time.time() - 1000  # 1000 секунд назад
        
        # Симулируем старые попытки
        self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"] = {
            "attempts": 5,
            "window_start": old_time
        }
        
        # Act
        result = self.limiter._is_allowed(identifier, endpoint)
        
        # Assert
        assert result is True

    def test_record_attempt_new_client(self):
        """Тест записи попытки для нового клиента"""
        # Arrange
        identifier = "new_client"
        endpoint = "login"
        
        # Act
        self.limiter._record_attempt(identifier, endpoint)
        
        # Assert
        key = f"rate_limit:{identifier}:{endpoint}"
        assert key in self.limiter._storage
        assert self.limiter._storage[key]["attempts"] == 1
        assert isinstance(self.limiter._storage[key]["window_start"], float)

    def test_record_attempt_existing_client(self):
        """Тест записи попытки для существующего клиента"""
        # Arrange
        identifier = "existing_client"
        endpoint = "login"
        current_time = time.time()
        
        self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"] = {
            "attempts": 2,
            "window_start": current_time
        }
        
        # Act
        self.limiter._record_attempt(identifier, endpoint)
        
        # Assert
        assert self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"]["attempts"] == 3

    def test_record_attempt_window_expired(self):
        """Тест записи попытки после истечения окна"""
        # Arrange
        identifier = "test_client"
        endpoint = "login"
        old_time = time.time() - 1000
        
        self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"] = {
            "attempts": 5,
            "window_start": old_time
        }
        
        # Act
        self.limiter._record_attempt(identifier, endpoint)
        
        # Assert
        # Должен сброситься счетчик
        assert self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"]["attempts"] == 1

    def test_check_rate_limit_allowed(self):
        """Тест проверки rate limit - разрешено"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        
        # Act
        result = self.limiter.check_rate_limit(mock_request, "login")
        
        # Assert
        assert result is True

    def test_check_rate_limit_exceeded(self):
        """Тест проверки rate limit - превышен"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        
        # Исчерпываем лимит
        for _ in range(3):
            self.limiter.check_rate_limit(mock_request, "login")
        
        # Act
        result = self.limiter.check_rate_limit(mock_request, "login")
        
        # Assert
        assert result is False

    def test_check_rate_limit_different_endpoints(self):
        """Тест проверки rate limit для разных эндпоинтов"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        
        # Исчерпываем лимит для login
        for _ in range(3):
            self.limiter.check_rate_limit(mock_request, "login")
        
        # Act
        result = self.limiter.check_rate_limit(mock_request, "register")
        
        # Assert
        assert result is True  # Лимит для register отдельный

    def test_check_rate_limit_different_clients(self):
        """Тест проверки rate limit для разных клиентов"""
        # Arrange
        mock_request1 = Mock(spec=Request)
        mock_request1.client.host = "192.168.1.1"
        mock_request1.headers = {"user-agent": "Mozilla/5.0"}
        
        mock_request2 = Mock(spec=Request)
        mock_request2.client.host = "192.168.1.2"
        mock_request2.headers = {"Mozilla/5.0"}
        
        # Исчерпываем лимит для первого клиента
        for _ in range(3):
            self.limiter.check_rate_limit(mock_request1, "login")
        
        # Act
        result = self.limiter.check_rate_limit(mock_request2, "login")
        
        # Assert
        assert result is True  # Второй клиент может

    def test_get_retry_after(self):
        """Тест получения времени до следующей попытки"""
        # Arrange
        identifier = "test_client"
        endpoint = "login"
        current_time = time.time()
        
        # Симулируем превышение лимита
        self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"] = {
            "attempts": 3,
            "window_start": current_time
        }
        
        # Act
        retry_after = self.limiter._get_retry_after(identifier, endpoint)
        
        # Assert
        assert isinstance(retry_after, int)
        assert retry_after > 0
        assert retry_after <= 900  # window для login

    def test_get_retry_after_window_expired(self):
        """Тест получения времени до следующей попытки после истечения окна"""
        # Arrange
        identifier = "test_client"
        endpoint = "login"
        old_time = time.time() - 1000
        
        self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"] = {
            "attempts": 3,
            "window_start": old_time
        }
        
        # Act
        retry_after = self.limiter._get_retry_after(identifier, endpoint)
        
        # Assert
        assert retry_after == 0  # Окно истекло

    def test_get_retry_after_no_data(self):
        """Тест получения времени до следующей попытки без данных"""
        # Arrange
        identifier = "new_client"
        endpoint = "login"
        
        # Act
        retry_after = self.limiter._get_retry_after(identifier, endpoint)
        
        # Assert
        assert retry_after == 0

    def test_cleanup_expired_entries(self):
        """Тест очистки устаревших записей"""
        # Arrange
        current_time = time.time()
        old_time = current_time - 1000
        
        # Создаем смесь старых и новых записей
        self.limiter._storage["rate_limit:old_client:login"] = {
            "attempts": 3,
            "window_start": old_time
        }
        self.limiter._storage["rate_limit:new_client:login"] = {
            "attempts": 1,
            "window_start": current_time
        }
        
        # Act
        self.limiter._cleanup_expired_entries()
        
        # Assert
        assert "rate_limit:old_client:login" not in self.limiter._storage
        assert "rate_limit:new_client:login" in self.limiter._storage

    def test_get_limits_for_endpoint_auth(self):
        """Тест получения лимитов для аутентификационного эндпоинта"""
        # Act
        limits = self.limiter._get_limits_for_endpoint("login")
        
        # Assert
        assert limits == self.limiter.auth_limits["login"]

    def test_get_limits_for_endpoint_general(self):
        """Тест получения лимитов для общего эндпоинта"""
        # Act
        limits = self.limiter._get_limits_for_endpoint("api")
        
        # Assert
        assert limits == self.limiter.general_limits["api"]

    def test_get_limits_for_endpoint_unknown(self):
        """Тест получения лимитов для неизвестного эндпоинта"""
        # Act
        limits = self.limiter._get_limits_for_endpoint("unknown")
        
        # Assert
        assert limits == self.limiter.general_limits["api"]  # По умолчанию

    def test_get_limits_for_endpoint_file_upload(self):
        """Тест получения лимитов для загрузки файлов"""
        # Act
        limits = self.limiter._get_limits_for_endpoint("file_upload")
        
        # Assert
        assert limits == self.limiter.general_limits["file_upload"]

    def test_get_limits_for_endpoint_ai_chat(self):
        """Тест получения лимитов для AI чата"""
        # Act
        limits = self.limiter._get_limits_for_endpoint("ai_chat")
        
        # Assert
        assert limits == self.limiter.general_limits["ai_chat"]

    def test_get_limits_for_endpoint_register(self):
        """Тест получения лимитов для регистрации"""
        # Act
        limits = self.limiter._get_limits_for_endpoint("register")
        
        # Assert
        assert limits == self.limiter.auth_limits["register"]

    def test_get_limits_for_endpoint_password_reset(self):
        """Тест получения лимитов для сброса пароля"""
        # Act
        limits = self.limiter._get_limits_for_endpoint("password_reset")
        
        # Assert
        assert limits == self.limiter.auth_limits["password_reset"]

    @patch('backend.middleware.secure_rate_limiter.time.time')
    def test_time_based_operations(self, mock_time):
        """Тест операций с моком времени"""
        # Arrange
        mock_time.return_value = 1000.0
        identifier = "test_client"
        endpoint = "login"
        
        # Act
        self.limiter._record_attempt(identifier, endpoint)
        result = self.limiter._is_allowed(identifier, endpoint)
        
        # Assert
        assert result is True
        assert self.limiter._storage[f"rate_limit:{identifier}:{endpoint}"]["window_start"] == 1000.0

    def test_concurrent_operations(self):
        """Тест конкурентных операций (упрощенный)"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        
        # Act - симулируем несколько быстрых запросов
        results = []
        for _ in range(5):
            results.append(self.limiter.check_rate_limit(mock_request, "login"))
        
        # Assert
        assert results[0] is True  # Первый разрешен
        assert results[1] is True  # Второй разрешен
        assert results[2] is True  # Третий разрешен
        assert results[3] is False  # Четвертый заблокирован
        assert results[4] is False  # Пятый заблокирован

    def test_storage_persistence_simulation(self):
        """Тест симуляции персистентности хранилища"""
        # Arrange
        identifier = "test_client"
        endpoint = "login"
        
        # Act
        self.limiter._record_attempt(identifier, endpoint)
        
        # Симулируем что данные сохранились
        stored_data = self.limiter._storage.copy()
        
        # Создаем новый лимитер и загружаем данные
        new_limiter = SecureRateLimiter()
        new_limiter._storage = stored_data
        
        # Assert
        result = new_limiter._is_allowed(identifier, endpoint)
        assert result is True  # Данные сохранились

    def test_edge_case_empty_headers(self):
        """Тест крайнего случая с пустыми заголовками"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {}
        
        # Act
        identifier = self.limiter._get_client_identifier(mock_request)
        
        # Assert
        assert isinstance(identifier, str)
        assert len(identifier) == 16

    def test_edge_case_none_client(self):
        """Тест крайнего случая с None client"""
        # Arrange
        mock_request = Mock(spec=Request)
        mock_request.client = None
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        
        # Act
        identifier = self.limiter._get_client_identifier(mock_request)
        
        # Assert
        assert isinstance(identifier, str)
        assert len(identifier) == 16