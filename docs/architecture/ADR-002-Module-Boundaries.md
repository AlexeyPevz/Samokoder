# ADR-002: Module Boundaries and Contracts

**Статус:** Принято  
**Дата:** 2025-01-27  
**Участники:** CTO, Lead Architect, Senior Developers

## Контекст

Проект "Самокодер" требует четкого разделения модулей и определения контрактов между ними для обеспечения maintainability и testability.

## Проблема

Текущая архитектура имеет некоторые нарушения принципов SOLID и Clean Architecture:
- Смешанные уровни абстракции
- Нечеткие границы между модулями
- Отсутствие явных контрактов

## Решение

### Архитектурные слои

```
┌─────────────────────────────────────┐
│           Presentation Layer        │
│  (FastAPI routes, middleware)       │
├─────────────────────────────────────┤
│           Application Layer         │
│  (Services, use cases, DTOs)       │
├─────────────────────────────────────┤
│           Domain Layer              │
│  (Models, business logic)           │
├─────────────────────────────────────┤
│           Infrastructure Layer      │
│  (Database, external APIs)          │
└─────────────────────────────────────┘
```

### Модульные границы

#### 1. **Presentation Layer**
- `backend/main_improved.py` - API endpoints
- `backend/middleware/` - Cross-cutting concerns
- `backend/models/requests.py` - Input DTOs
- `backend/models/responses.py` - Output DTOs

#### 2. **Application Layer**
- `backend/services/` - Business logic
- `backend/auth/` - Authentication logic
- `backend/monitoring/` - Observability

#### 3. **Domain Layer**
- `backend/models/` - Domain models
- Business rules and validation

#### 4. **Infrastructure Layer**
- `backend/services/connection_pool.py` - Database access
- `backend/services/ai_service.py` - External AI APIs
- `config/` - Configuration management

### Контракты между модулями

#### Service Contracts
```python
# Abstract base classes for services
class AIServiceProtocol(Protocol):
    async def chat_completion(self, request: AIRequest) -> AIResponse: ...
    async def validate_api_key(self) -> bool: ...

class DatabaseServiceProtocol(Protocol):
    async def get_user(self, user_id: str) -> Optional[User]: ...
    async def create_project(self, project: Project) -> Project: ...
```

#### Repository Pattern
```python
class UserRepository(Protocol):
    async def find_by_id(self, user_id: str) -> Optional[User]: ...
    async def save(self, user: User) -> User: ...
    async def delete(self, user_id: str) -> None: ...
```

### Dependency Injection

```python
# Container для DI
class Container:
    def __init__(self):
        self._services = {}
    
    def register(self, interface: Type, implementation: Type):
        self._services[interface] = implementation
    
    def get(self, interface: Type):
        return self._services[interface]()
```

## Реализация

### 1. Создание интерфейсов
```python
# backend/contracts/ai_service.py
from abc import ABC, abstractmethod
from typing import Protocol

class AIServiceContract(Protocol):
    async def chat_completion(self, request: AIRequest) -> AIResponse: ...
    async def validate_api_key(self) -> bool: ...
    async def get_usage_stats(self) -> Dict[str, Any]: ...
```

### 2. Рефакторинг сервисов
```python
# backend/services/ai_service_impl.py
class AIServiceImpl(AIServiceContract):
    def __init__(self, config: AIConfig, logger: Logger):
        self.config = config
        self.logger = logger
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        # Implementation
        pass
```

### 3. Dependency Injection Container
```python
# backend/container.py
class DIContainer:
    def __init__(self):
        self._services = {}
        self._setup_defaults()
    
    def _setup_defaults(self):
        self.register(AIServiceContract, AIServiceImpl)
        self.register(DatabaseServiceContract, DatabaseServiceImpl)
```

## Миграционный план

### Фаза 1: Создание контрактов (1 неделя)
- [ ] Создать интерфейсы для всех сервисов
- [ ] Определить Repository паттерны
- [ ] Создать DI Container

### Фаза 2: Рефакторинг сервисов (2 недели)
- [ ] Выделить реализации из интерфейсов
- [ ] Внедрить DI в main_improved.py
- [ ] Обновить тесты

### Фаза 3: Валидация (1 неделя)
- [ ] Проверить все зависимости
- [ ] Обновить документацию
- [ ] Performance тестирование

## Последствия

### Положительные
- Четкое разделение ответственности
- Легкое тестирование с моками
- Гибкость в замене реализаций
- Соответствие SOLID принципам

### Негативные
- Увеличение сложности кода
- Больше абстракций
- Время на рефакторинг

## Альтернативы

1. **Текущий подход** - отклонено из-за tight coupling
2. **Microservices** - рассмотрено, но слишком рано
3. **Event-driven** - рассмотрено для будущих версий

## Мониторинг

- Code coverage для контрактов
- Dependency graph анализ
- Performance impact measurement
- Architecture decision tracking