"""
Circuit Breaker Pattern Implementation
"""
import asyncio
import time
import structlog
from enum import Enum
from typing import Callable, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = structlog.get_logger(__name__)

class CircuitState(Enum):
    """Circuit Breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, failing fast
    HALF_OPEN = "half_open"  # Testing if service is back

@dataclass
class CircuitBreakerConfig:
    """Circuit Breaker configuration"""
    failure_threshold: int = 5          # Number of failures before opening
    recovery_timeout: int = 60          # Seconds to wait before trying again
    success_threshold: int = 3          # Successes needed to close from half-open
    timeout: int = 30                   # Timeout for individual calls
    expected_exception: tuple = (Exception,)  # Exceptions that count as failures

class CircuitBreaker:
    """Circuit Breaker implementation with thread safety"""
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_success_time = None
        self._lock = asyncio.Lock()
        
        logger.info("circuit_breaker_initialized", name=name, config=self.config.__dict__)
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        
        async with self._lock:
            # Check if circuit is open and should remain open
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    logger.info("circuit_breaker_half_open", name=self.name)
                else:
                    raise CircuitBreakerOpenException(f"Circuit breaker '{self.name}' is OPEN")
        
        # Execute the function with timeout
        try:
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=self.config.timeout
            )
            
            # Handle success
            await self._on_success()
            return result
            
        except asyncio.TimeoutError:
            await self._on_failure("Timeout")
            raise CircuitBreakerTimeoutException(f"Circuit breaker '{self.name}' timeout")
            
        except self.config.expected_exception as e:
            await self._on_failure(str(e))
            raise
            
        except Exception as e:
            # Unexpected exception - count as failure
            await self._on_failure(str(e))
            raise CircuitBreakerException(f"Circuit breaker '{self.name}' unexpected error: {e}")
    
    async def _on_success(self):
        """Handle successful call"""
        async with self._lock:
            self.last_success_time = datetime.now()
            
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                logger.debug("circuit_breaker_success", name=self.name, success_count=self.success_count)
                
                if self.success_count >= self.config.success_threshold:
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
                    logger.info("circuit_breaker_closed", name=self.name)
            
            elif self.state == CircuitState.CLOSED:
                # Reset failure count on success
                self.failure_count = 0
    
    async def _on_failure(self, error: str):
        """Handle failed call"""
        async with self._lock:
            self.last_failure_time = datetime.now()
            self.failure_count += 1
            
            logger.warning("circuit_breaker_failure", name=self.name, failure_count=self.failure_count, error=str(error))
            
            if self.state == CircuitState.HALF_OPEN:
                # Any failure in half-open state opens the circuit
                self.state = CircuitState.OPEN
                logger.warning("circuit_breaker_open_from_half_open", name=self.name)
                
            elif self.state == CircuitState.CLOSED and self.failure_count >= self.config.failure_threshold:
                # Too many failures, open the circuit
                self.state = CircuitState.OPEN
                logger.warning("circuit_breaker_open", name=self.name)
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return True
        
        time_since_failure = datetime.now() - self.last_failure_time
        return time_since_failure >= timedelta(seconds=self.config.recovery_timeout)
    
    def get_state(self) -> dict:
        """Get current circuit breaker state"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout
            }
        }
    
    def reset(self):
        """Manually reset circuit breaker"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_success_time = None
        logger.info("circuit_breaker_reset", name=self.name)

class CircuitBreakerException(Exception):
    """Base exception for circuit breaker"""
    pass

class CircuitBreakerOpenException(CircuitBreakerException):
    """Exception raised when circuit breaker is open"""
    pass

class CircuitBreakerTimeoutException(CircuitBreakerException):
    """Exception raised when circuit breaker times out"""
    pass

class CircuitBreakerManager:
    """Manager for multiple circuit breakers"""
    
    def __init__(self):
        self._breakers: dict[str, CircuitBreaker] = {}
    
    def get_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create circuit breaker"""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, config)
        return self._breakers[name]
    
    def get_all_states(self) -> dict:
        """Get states of all circuit breakers"""
        return {name: breaker.get_state() for name, breaker in self._breakers.items()}
    
    def reset_breaker(self, name: str):
        """Reset specific circuit breaker"""
        if name in self._breakers:
            self._breakers[name].reset()
    
    def reset_all(self):
        """Reset all circuit breakers"""
        for breaker in self._breakers.values():
            breaker.reset()

# Global circuit breaker manager
circuit_breaker_manager = CircuitBreakerManager()

# Decorator for easy circuit breaker usage
def circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """Decorator to add circuit breaker to a function"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            breaker = circuit_breaker_manager.get_breaker(name, config)
            return await breaker.call(func, *args, **kwargs)
        return wrapper
    return decorator