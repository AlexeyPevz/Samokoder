# ADR-AUDIT-005: Экстернализация параметров Circuit Breaker

## Статус
Принято

## Контекст
Circuit Breaker имеет захардкоженные значения timeout и thresholds, что затрудняет настройку отказоустойчивости.

## Проблема
**Файл**: `backend/patterns/circuit_breaker.py:20-26`

```python
@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5          # Захардкожено!
    recovery_timeout: int = 60          # Захардкожено!
    success_threshold: int = 3          # Захардкожено!
    timeout: int = 30                   # Захардкожено!
```

### Последствия
- Невозможность настройки для разных сервисов без изменения кода
- Одинаковые параметры для всех внешних интеграций
- Сложность адаптации под load profile production

## Решение

### 1. Добавить конфигурацию в settings
```python
# config/settings.py
class Settings(BaseSettings):
    # Circuit Breaker
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 60
    circuit_breaker_success_threshold: int = 3
    circuit_breaker_timeout: int = 30
    
    # Специфичные настройки для критичных сервисов
    circuit_breaker_ai_timeout: int = 60  # AI может работать дольше
    circuit_breaker_db_timeout: int = 10  # DB должна отвечать быстро
```

### 2. Создать фабрику конфигураций
```python
# backend/patterns/circuit_breaker.py
from config.settings import settings

def get_circuit_breaker_config(service_type: str = "default") -> CircuitBreakerConfig:
    """Получить конфигурацию circuit breaker для типа сервиса"""
    configs = {
        "ai": CircuitBreakerConfig(
            failure_threshold=settings.circuit_breaker_failure_threshold,
            recovery_timeout=settings.circuit_breaker_recovery_timeout,
            success_threshold=settings.circuit_breaker_success_threshold,
            timeout=settings.circuit_breaker_ai_timeout
        ),
        "database": CircuitBreakerConfig(
            timeout=settings.circuit_breaker_db_timeout
        ),
        "default": CircuitBreakerConfig(
            failure_threshold=settings.circuit_breaker_failure_threshold,
            recovery_timeout=settings.circuit_breaker_recovery_timeout,
            success_threshold=settings.circuit_breaker_success_threshold,
            timeout=settings.circuit_breaker_timeout
        )
    }
    return configs.get(service_type, configs["default"])
```

### 3. Использование
```python
# backend/adapters/ai_adapter.py
from backend.patterns.circuit_breaker import get_circuit_breaker_config

class AIAdapter:
    def __init__(self):
        self.circuit_breaker = CircuitBreaker(
            "ai_service",
            config=get_circuit_breaker_config("ai")
        )
```

### 4. Добавить в .env.example
```bash
# Circuit Breaker Configuration
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60
CIRCUIT_BREAKER_SUCCESS_THRESHOLD=3
CIRCUIT_BREAKER_TIMEOUT=30

# Service-specific timeouts
CIRCUIT_BREAKER_AI_TIMEOUT=60
CIRCUIT_BREAKER_DB_TIMEOUT=10
```

## Последствия
- ✅ Гибкая настройка отказоустойчивости через env vars
- ✅ Разные параметры для разных типов сервисов
- ✅ Быстрая адаптация под load без деплоя
- ✅ Мониторинг через изменение порогов
- ⚠️ Требует документации параметров

## Связанные файлы
- `backend/patterns/circuit_breaker.py:20-26`
- `config/settings.py`
- `.env.example`
