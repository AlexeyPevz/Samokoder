"""
Упрощенные тесты для CircuitBreaker (39% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncio
from datetime import datetime, timedelta

from backend.patterns.circuit_breaker import (
    CircuitBreaker,
    CircuitState,
    CircuitBreakerConfig
)


class TestCircuitBreakerConfig:
    """Тесты для CircuitBreakerConfig"""

    def test_init_default(self):
        """Тест инициализации с параметрами по умолчанию"""
        config = CircuitBreakerConfig()
        
        assert config.failure_threshold == 5
        assert config.recovery_timeout == 60
        assert config.success_threshold == 3
        assert config.timeout == 30
        assert config.expected_exception == (Exception,)

    def test_init_custom(self):
        """Тест инициализации с кастомными параметрами"""
        config = CircuitBreakerConfig(
            failure_threshold=10,
            recovery_timeout=120,
            success_threshold=5,
            timeout=60,
            expected_exception=(ValueError, RuntimeError)
        )
        
        assert config.failure_threshold == 10
        assert config.recovery_timeout == 120
        assert config.success_threshold == 5
        assert config.timeout == 60
        assert config.expected_exception == (ValueError, RuntimeError)


class TestCircuitBreaker:
    """Тесты для CircuitBreaker"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=60,
            success_threshold=2,
            timeout=10
        )
        self.circuit = CircuitBreaker("test_circuit", self.config)

    def test_init_default_config(self):
        """Тест инициализации с конфигурацией по умолчанию"""
        circuit = CircuitBreaker("test")
        
        assert circuit.name == "test"
        assert circuit.config.failure_threshold == 5
        assert circuit.state == CircuitState.CLOSED
        assert circuit.failure_count == 0
        assert circuit.success_count == 0
        assert circuit.last_failure_time is None
        assert circuit.last_success_time is None

    def test_init_custom_config(self):
        """Тест инициализации с кастомной конфигурацией"""
        circuit = CircuitBreaker("test", self.config)
        
        assert circuit.name == "test"
        assert circuit.config == self.config
        assert circuit.state == CircuitState.CLOSED
        assert circuit.failure_count == 0
        assert circuit.success_count == 0

    @pytest.mark.asyncio
    async def test_call_success_closed_state(self):
        """Тест успешного вызова в закрытом состоянии"""
        # Arrange
        mock_func = AsyncMock(return_value="success")
        
        # Act
        result = await self.circuit.call(mock_func, "arg1", "arg2", key="value")
        
        # Assert
        assert result == "success"
        assert self.circuit.state == CircuitState.CLOSED
        assert self.circuit.failure_count == 0
        mock_func.assert_called_once_with("arg1", "arg2", key="value")

    @pytest.mark.asyncio
    async def test_call_failure_closed_state(self):
        """Тест неудачного вызова в закрытом состоянии"""
        # Arrange
        mock_func = AsyncMock(side_effect=Exception("Test error"))
        
        # Act
        with pytest.raises(Exception) as exc_info:
            await self.circuit.call(mock_func)
        
        # Assert
        assert "Test error" in str(exc_info.value)
        assert self.circuit.state == CircuitState.CLOSED
        assert self.circuit.failure_count == 1
        assert self.circuit.last_failure_time is not None

    @pytest.mark.asyncio
    async def test_call_failure_threshold_reached(self):
        """Тест достижения порога неудач"""
        # Arrange
        mock_func = AsyncMock(side_effect=Exception("Test error"))
        
        # Act - делаем несколько неудачных вызовов
        for _ in range(3):
            with pytest.raises(Exception):
                await self.circuit.call(mock_func)
        
        # Assert
        assert self.circuit.state == CircuitState.OPEN
        assert self.circuit.failure_count == 3

    @pytest.mark.asyncio
    async def test_call_open_state_fails_fast(self):
        """Тест быстрого отказа в открытом состоянии"""
        # Arrange
        self.circuit.state = CircuitState.OPEN
        self.circuit.last_failure_time = datetime.now()
        mock_func = AsyncMock(return_value="should_not_call")
        
        # Act
        with pytest.raises(Exception) as exc_info:
            await self.circuit.call(mock_func)
        
        # Assert
        assert "Circuit breaker" in str(exc_info.value) and "OPEN" in str(exc_info.value)
        mock_func.assert_not_called()

    @pytest.mark.asyncio
    async def test_call_open_state_reset_timeout(self):
        """Тест сброса таймаута в открытом состоянии"""
        # Arrange
        self.circuit.state = CircuitState.OPEN
        # Устанавливаем время последней неудачи в прошлом
        self.circuit.last_failure_time = datetime.now() - timedelta(seconds=70)
        mock_func = AsyncMock(return_value="success")
        
        # Act
        result = await self.circuit.call(mock_func)
        
        # Assert
        assert result == "success"
        assert self.circuit.state == CircuitState.HALF_OPEN
        mock_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_half_open_success(self):
        """Тест успешного вызова в полуоткрытом состоянии"""
        # Arrange - устанавливаем success_threshold=2 для быстрого тестирования
        self.circuit.config.success_threshold = 2
        self.circuit.state = CircuitState.HALF_OPEN
        self.circuit.success_count = 1
        mock_func = AsyncMock(return_value="success")
        
        # Act
        result = await self.circuit.call(mock_func)
        
        # Assert
        assert result == "success"
        assert self.circuit.state == CircuitState.CLOSED
        # После достижения success_threshold счетчик сбрасывается
        assert self.circuit.success_count == 0
        assert self.circuit.failure_count == 0
        mock_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_half_open_failure(self):
        """Тест неудачного вызова в полуоткрытом состоянии"""
        # Arrange
        self.circuit.state = CircuitState.HALF_OPEN
        mock_func = AsyncMock(side_effect=Exception("Test error"))
        
        # Act
        with pytest.raises(Exception):
            await self.circuit.call(mock_func)
        
        # Assert
        assert self.circuit.state == CircuitState.OPEN
        assert self.circuit.failure_count == 1
        mock_func.assert_called_once()

    def test_should_attempt_reset_true(self):
        """Тест проверки возможности сброса - можно"""
        # Arrange
        self.circuit.last_failure_time = datetime.now() - timedelta(seconds=70)
        
        # Act
        result = self.circuit._should_attempt_reset()
        
        # Assert
        assert result is True

    def test_should_attempt_reset_false(self):
        """Тест проверки возможности сброса - нельзя"""
        # Arrange
        self.circuit.last_failure_time = datetime.now() - timedelta(seconds=30)
        
        # Act
        result = self.circuit._should_attempt_reset()
        
        # Assert
        assert result is False

    def test_should_attempt_reset_no_failure_time(self):
        """Тест проверки возможности сброса - нет времени неудачи"""
        # Arrange
        self.circuit.last_failure_time = None
        
        # Act
        result = self.circuit._should_attempt_reset()
        
        # Assert
        assert result is True  # Когда нет времени неудачи, можно попробовать сброс

    def test_get_state(self):
        """Тест получения состояния"""
        # Arrange
        self.circuit.failure_count = 2
        self.circuit.success_count = 1
        self.circuit.last_failure_time = datetime.now()
        
        # Act
        state = self.circuit.get_state()
        
        # Assert
        assert "name" in state
        assert "state" in state
        assert "failure_count" in state
        assert "success_count" in state
        assert state["name"] == "test_circuit"
        assert state["state"] == "closed"  # Возвращает строку, а не enum

    def test_reset(self):
        """Тест сброса состояния"""
        # Arrange
        self.circuit.failure_count = 5
        self.circuit.success_count = 2
        self.circuit.last_failure_time = datetime.now()
        
        # Act
        self.circuit.reset()
        
        # Assert
        assert self.circuit.failure_count == 0
        assert self.circuit.success_count == 0
        assert self.circuit.last_failure_time is None
        assert self.circuit.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_concurrent_calls(self):
        """Тест конкурентных вызовов"""
        # Arrange
        mock_func = AsyncMock(return_value="success")
        
        # Act - создаем несколько задач одновременно
        tasks = [self.circuit.call(mock_func) for _ in range(5)]
        results = await asyncio.gather(*tasks)
        
        # Assert
        assert all(result == "success" for result in results)
        assert mock_func.call_count == 5

    @pytest.mark.asyncio
    async def test_concurrent_failures(self):
        """Тест конкурентных неудач"""
        # Arrange
        mock_func = AsyncMock(side_effect=Exception("Test error"))
        
        # Act - создаем несколько задач с неудачами
        tasks = [self.circuit.call(mock_func) for _ in range(5)]
        
        with pytest.raises(Exception):
            await asyncio.gather(*tasks)
        
        # Assert
        # После 3 неудач circuit breaker переходит в OPEN состояние
        assert self.circuit.failure_count >= 3
        assert self.circuit.state == CircuitState.OPEN