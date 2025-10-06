# ADR-AUDIT-002: Нарушение границ модулей в API слое

## Статус
Принято

## Контекст
API слой напрямую импортирует сервисы, нарушая принципы слоистой архитектуры и инверсии зависимостей.

## Проблема
**Файлы с нарушениями**:
- `backend/api/ai.py:10` - `from backend.services.ai_service import get_ai_service`
- `backend/api/api_keys.py` - прямой импорт сервисов
- `backend/api/rbac.py` - прямой импорт сервисов
- `backend/api/mfa.py` - прямой импорт сервисов

### Последствия
- Тесная связанность модулей
- Невозможность легкой замены реализаций
- Сложность unit-тестирования (нельзя мокировать через DI)
- Нарушение Dependency Inversion Principle

## Решение
Использовать Dependency Injection через FastAPI Depends с контрактами:

```python
# backend/api/ai.py
from backend.contracts.ai_service import AIServiceProtocol
from backend.core.dependency_injection import get_container

def get_ai_service() -> AIServiceProtocol:
    """Get AI service from DI container"""
    return get_container().get(AIServiceProtocol)

@router.post("/chat")
async def chat_with_ai(
    ai_service: AIServiceProtocol = Depends(get_ai_service),
    ...
):
    response = await ai_service.chat_completion(ai_request)
```

### Минимальный патч
Создать dependency providers в `backend/api/dependencies.py`:

```python
from backend.contracts import AIServiceProtocol
from backend.core.dependency_injection import get_container

def provide_ai_service() -> AIServiceProtocol:
    return get_container().get(AIServiceProtocol)
```

## Последствия
- ✅ Соблюдение слоистой архитектуры
- ✅ Легкая замена реализаций
- ✅ Улучшенная тестируемость
- ⚠️ Требует регистрации сервисов в DI контейнере

## Связанные файлы
- `backend/api/ai.py:10`
- `backend/api/api_keys.py`
- `backend/api/rbac.py`
- `backend/api/mfa.py`
- `backend/core/dependency_injection.py`
