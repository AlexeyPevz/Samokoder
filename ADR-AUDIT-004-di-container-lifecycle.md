# ADR-AUDIT-004: Исправление жизненного цикла DI контейнера

## Статус
Принято

## Контекст
DI контейнер использует `lru_cache` с классами вместо экземпляров, что может привести к утечкам памяти и некорректному поведению.

## Проблема
**Файл**: `backend/core/dependency_injection.py:162-190`

```python
@lru_cache()
def get_rbac_service():
    """Получить RBAC сервис"""
    container = get_container()
    return container.get(RBACService)  # RBACService - это класс, не протокол!
```

### Проблемы:
1. `lru_cache` кэширует по сигнатуре функции (без аргументов), создавая глобальный singleton
2. Импортирование конкретных классов нарушает инверсию зависимостей
3. Циклические импорты из-за прямых ссылок на классы
4. Невозможность тестирования с моками

## Решение

### 1. Использовать протоколы вместо классов
```python
# backend/core/dependency_injection.py
from backend.contracts import (
    AIServiceProtocol,
    RBACServiceProtocol,
    MFAServiceProtocol
)

def get_rbac_service() -> RBACServiceProtocol:
    """Получить RBAC сервис из контейнера"""
    container = get_container()
    return container.get(RBACServiceProtocol)

# Убрать @lru_cache() - контейнер сам управляет singleton
```

### 2. Регистрация через протоколы
```python
# backend/core/dependency_injection.py
def _setup_default_services():
    container = get_container()
    
    from backend.services.rbac_service import RBACService
    from backend.contracts import RBACServiceProtocol
    
    # Регистрируем протокол -> реализация
    container.register_singleton(RBACServiceProtocol, RBACService)
```

### 3. Добавить недостающие протоколы
```python
# backend/contracts/rbac.py
from typing import Protocol
from uuid import UUID

class RBACServiceProtocol(Protocol):
    async def check_permission(self, user_id: UUID, resource: str, action: str) -> bool:
        ...
    
    async def assign_role(self, user_id: UUID, role: str) -> bool:
        ...
```

## Последствия
- ✅ Правильный lifecycle management
- ✅ Соблюдение Dependency Inversion Principle
- ✅ Избежание циклических импортов
- ✅ Улучшенная тестируемость
- ⚠️ Требует создания протоколов для всех сервисов

## Связанные файлы
- `backend/core/dependency_injection.py:162-190`
- `backend/contracts/rbac.py` (нужно создать)
- `backend/contracts/mfa.py` (нужно создать)
