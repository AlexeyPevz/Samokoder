"""
Integration tests for Circuit Breaker
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from backend.patterns.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState

class TestCircuitBreakerIntegration:
    """Integration tests for Circuit Breaker"""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_success(self):
        """Test successful circuit breaker operation"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=1,
            success_threshold=2,
            timeout=5
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock successful function
        async def success_func():
            return "success"
        
        # Call function
        result = await breaker.call(success_func)
        
        # Should return success
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_failure_threshold(self):
        """Test circuit breaker opening after failure threshold"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=1,
            success_threshold=2,
            timeout=5
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock failing function
        async def fail_func():
            raise Exception("test error")
        
        # First failure
        with pytest.raises(Exception):
            await breaker.call(fail_func)
        assert breaker.state == CircuitState.CLOSED
        
        # Second failure - should open circuit
        with pytest.raises(Exception):
            await breaker.call(fail_func)
        assert breaker.state == CircuitState.OPEN
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_open_state(self):
        """Test circuit breaker in open state"""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=1,
            success_threshold=1,
            timeout=5
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock failing function
        async def fail_func():
            raise Exception("test error")
        
        # Trigger failure to open circuit
        with pytest.raises(Exception):
            await breaker.call(fail_func)
        
        assert breaker.state == CircuitState.OPEN
        
        # Try to call function - should fail fast
        with pytest.raises(Exception) as exc_info:
            await breaker.call(fail_func)
        assert "is OPEN" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker recovery from half-open state"""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=0.1,  # Very short timeout
            success_threshold=1,
            timeout=5
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock failing function
        async def fail_func():
            raise Exception("test error")
        
        # Trigger failure to open circuit
        with pytest.raises(Exception):
            await breaker.call(fail_func)
        
        assert breaker.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        await asyncio.sleep(0.2)
        
        # Mock successful function
        async def success_func():
            return "success"
        
        # Should transition to half-open and then closed
        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_timeout(self):
        """Test circuit breaker timeout handling"""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=1,
            success_threshold=1,
            timeout=0.1  # Very short timeout
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock slow function
        async def slow_func():
            await asyncio.sleep(1)
            return "success"
        
        # Should timeout
        with pytest.raises(Exception) as exc_info:
            await breaker.call(slow_func)
        assert "timeout" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_thread_safety(self):
        """Test circuit breaker thread safety"""
        config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=1,
            success_threshold=3,
            timeout=5
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock function that sometimes fails
        call_count = 0
        async def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise Exception("test error")
            return "success"
        
        # Create multiple concurrent tasks
        tasks = []
        for _ in range(10):
            task = asyncio.create_task(breaker.call(flaky_func))
            tasks.append(task)
        
        # Wait for all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Some should succeed, some should fail
        successes = [r for r in results if r == "success"]
        failures = [r for r in results if isinstance(r, Exception)]
        
        assert len(successes) > 0
        assert len(failures) > 0
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_state_transitions(self):
        """Test circuit breaker state transitions"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,
            success_threshold=2,
            timeout=5
        )
        breaker = CircuitBreaker("test", config)
        
        # Start in CLOSED state
        assert breaker.state == CircuitState.CLOSED
        
        # Mock failing function
        async def fail_func():
            raise Exception("test error")
        
        # First failure - should stay CLOSED
        with pytest.raises(Exception):
            await breaker.call(fail_func)
        assert breaker.state == CircuitState.CLOSED
        
        # Second failure - should go to OPEN
        with pytest.raises(Exception):
            await breaker.call(fail_func)
        assert breaker.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        await asyncio.sleep(0.2)
        
        # Mock successful function
        async def success_func():
            return "success"
        
        # Should go to HALF_OPEN and then CLOSED
        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_metrics(self):
        """Test circuit breaker metrics"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=1,
            success_threshold=2,
            timeout=5
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock failing function
        async def fail_func():
            raise Exception("test error")
        
        # Trigger failures
        for _ in range(3):
            with pytest.raises(Exception):
                await breaker.call(fail_func)
        
        # Check metrics
        assert breaker.failure_count == 3
        assert breaker.state == CircuitState.OPEN
        assert breaker.last_failure_time is not None
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_custom_exceptions(self):
        """Test circuit breaker with custom exceptions"""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=1,
            success_threshold=1,
            timeout=5,
            expected_exception=(ValueError,)
        )
        breaker = CircuitBreaker("test", config)
        
        # Mock function that raises expected exception
        async def expected_error_func():
            raise ValueError("expected error")
        
        # Should count as failure
        with pytest.raises(ValueError):
            await breaker.call(expected_error_func)
        
        assert breaker.state == CircuitState.OPEN
        
        # Mock function that raises unexpected exception
        async def unexpected_error_func():
            raise RuntimeError("unexpected error")
        
        # Should not count as failure (but still raise)
        with pytest.raises(RuntimeError):
            await breaker.call(unexpected_error_func)
        
        # State should not change
        assert breaker.state == CircuitState.OPEN