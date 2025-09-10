# ADR-005: Minimal Fixes Without Breaking Changes

**Статус:** Принято  
**Дата:** 2025-01-27  
**Участники:** CTO, Lead Architect, Senior Developers

## Контекст

После архитектурного аудита выявлены минимальные исправления, которые можно внедрить без breaking changes для улучшения качества кода и архитектуры.

## Выявленные проблемы

### 1. 🔧 Критические (требуют немедленного исправления)

#### 1.1 Отсутствие системы миграций БД
**Проблема:** Статическая схема без версионирования
**Решение:** Внедрить Alembic (см. ADR-003)
**Приоритет:** Высокий
**Breaking Change:** Нет

#### 1.2 Секреты в .env файле
**Проблема:** Риск exposure секретов
**Решение:** Внедрить secret management (см. ADR-004)
**Приоритет:** Высокий
**Breaking Change:** Нет

### 2. ⚠️ Важные (требуют исправления в ближайшее время)

#### 2.1 Нарушение принципа единственной ответственности
**Проблема:** `main_improved.py` содержит 806 строк с множественными ответственностями
**Решение:** Разделить на модули
```python
# Текущее состояние
backend/main_improved.py (806 строк)

# Предлагаемое разделение
backend/
├── api/
│   ├── auth.py          # Аутентификация endpoints
│   ├── projects.py      # Проекты endpoints
│   ├── ai.py           # AI endpoints
│   └── health.py       # Health check endpoints
├── core/
│   ├── config.py       # Конфигурация
│   ├── dependencies.py # DI контейнер
│   └── exceptions.py   # Custom exceptions
└── main.py            # Только FastAPI app setup
```

#### 2.2 Отсутствие интерфейсов для сервисов
**Проблема:** Tight coupling между модулями
**Решение:** Внедрить Protocol-based интерфейсы
```python
# backend/contracts/ai_service.py
from typing import Protocol

class AIServiceProtocol(Protocol):
    async def chat_completion(self, request: AIRequest) -> AIResponse: ...
    async def validate_api_key(self) -> bool: ...
```

#### 2.3 Отсутствие dependency injection
**Проблема:** Hard-coded зависимости
**Решение:** Внедрить DI контейнер
```python
# backend/core/container.py
class DIContainer:
    def __init__(self):
        self._services = {}
    
    def register(self, interface: Type, implementation: Type):
        self._services[interface] = implementation
```

### 3. 📝 Улучшения (можно отложить)

#### 3.1 Добавить type hints везде
**Проблема:** Неполное покрытие type hints
**Решение:** Добавить mypy проверки в CI

#### 3.2 Улучшить error handling
**Проблема:** Generic error messages
**Решение:** Создать custom exception hierarchy

#### 3.3 Добавить circuit breaker
**Проблема:** Нет защиты от cascade failures
**Решение:** Внедрить circuit breaker pattern

## План реализации

### Неделя 1: Критические исправления
- [ ] Настроить Alembic для миграций
- [ ] Внедрить secret management
- [ ] Создать backup процедуры

### Неделя 2: Рефакторинг main.py
- [ ] Разделить на модули по ответственности
- [ ] Создать API routers
- [ ] Внедрить DI контейнер

### Неделя 3: Интерфейсы и контракты
- [ ] Создать Protocol-based интерфейсы
- [ ] Рефакторить сервисы под интерфейсы
- [ ] Обновить тесты

### Неделя 4: Улучшения
- [ ] Добавить type hints
- [ ] Улучшить error handling
- [ ] Внедрить circuit breaker

## Детальный план рефакторинга main.py

### Текущая структура
```python
# main_improved.py (806 строк)
- FastAPI app setup
- CORS middleware
- Error handlers
- Health check endpoints
- Auth endpoints
- Project endpoints
- AI endpoints
- Helper functions
```

### Предлагаемая структура
```python
# main.py (50 строк)
from fastapi import FastAPI
from backend.core.container import DIContainer
from backend.api import auth, projects, ai, health

def create_app() -> FastAPI:
    app = FastAPI(title="Samokoder API")
    
    # Register routers
    app.include_router(health.router, prefix="/health")
    app.include_router(auth.router, prefix="/api/auth")
    app.include_router(projects.router, prefix="/api/projects")
    app.include_router(ai.router, prefix="/api/ai")
    
    return app

# backend/api/auth.py (150 строк)
from fastapi import APIRouter, Depends
from backend.contracts.auth_service import AuthServiceProtocol

router = APIRouter()

@router.post("/login")
async def login(credentials: LoginRequest, 
                auth_service: AuthServiceProtocol = Depends(get_auth_service)):
    return await auth_service.authenticate(credentials)

# backend/api/projects.py (200 строк)
from fastapi import APIRouter, Depends
from backend.contracts.project_service import ProjectServiceProtocol

router = APIRouter()

@router.get("/")
async def get_projects(project_service: ProjectServiceProtocol = Depends(get_project_service)):
    return await project_service.list_projects()

# backend/core/container.py (100 строк)
class DIContainer:
    def __init__(self):
        self._services = {}
        self._setup_defaults()
    
    def _setup_defaults(self):
        self.register(AuthServiceProtocol, AuthServiceImpl)
        self.register(ProjectServiceProtocol, ProjectServiceImpl)
```

## Метрики успеха

### До рефакторинга
- `main_improved.py`: 806 строк
- Цикломатическая сложность: ~50
- Количество ответственностей: 8+
- Test coverage: 70%

### После рефакторинга
- `main.py`: ~50 строк
- Цикломатическая сложность: ~5
- Количество ответственностей: 1
- Test coverage: 90%+

## Риски и митигация

### Риск: Breaking changes
**Митигация:** Постепенный рефакторинг с сохранением API контрактов

### Риск: Performance degradation
**Митигация:** Performance тесты на каждом этапе

### Риск: Увеличение сложности
**Митигация:** Comprehensive документация и обучение команды

## Альтернативы

1. **Полный rewrite** - отклонено из-за рисков
2. **Микросервисы** - рассмотрено для будущих версий
3. **Текущее состояние** - отклонено из-за технического долга

## Мониторинг

- Code complexity metrics
- Test coverage tracking
- Performance benchmarks
- Error rate monitoring

## Заключение

Предлагаемые изменения улучшат:
- Maintainability кода
- Testability компонентов
- Scalability архитектуры
- Security конфигурации

Все изменения можно внедрить без breaking changes, постепенно улучшая качество кодовой базы.