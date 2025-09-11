# ADR-003: Усиление контрактов между модулями

## Статус
**ПРИНЯТО** - 2025-01-11

## Контекст
Аудит контрактов выявил недостаточное использование Protocol классов:

### Обнаруженные проблемы:
- **backend/contracts/__init__.py** - пустой файл, не экспортирует контракты
- **backend/repositories/** - прямые импорты вместо использования протоколов
- **backend/services/** - отсутствует проверка соответствия контрактам

### Риски:
1. **Нарушение принципа инверсии зависимостей**
2. **Сложность замены реализаций**
3. **Отсутствие compile-time проверок контрактов**
4. **Нарушение принципа подстановки Лисков**

## Решение
Внедрить **Contract Enforcement Pattern**:

### 1. Исправить backend/contracts/__init__.py
```python
# backend/contracts/__init__.py (ИСПРАВИТЬ)
from .database import (
    DatabaseServiceProtocol,
    UserRepositoryProtocol,
    ProjectRepositoryProtocol,
    ChatRepositoryProtocol
)
from .ai_service import AIServiceProtocol, AIProviderProtocol
from .auth import AuthServiceProtocol, PasswordServiceProtocol, TokenServiceProtocol
from .file_service import FileServiceProtocol, FileRepositoryProtocol
from .supabase_service import SupabaseServiceProtocol

__all__ = [
    # Database contracts
    "DatabaseServiceProtocol",
    "UserRepositoryProtocol", 
    "ProjectRepositoryProtocol",
    "ChatRepositoryProtocol",
    # AI contracts
    "AIServiceProtocol",
    "AIProviderProtocol",
    # Auth contracts
    "AuthServiceProtocol",
    "PasswordServiceProtocol", 
    "TokenServiceProtocol",
    # File contracts
    "FileServiceProtocol",
    "FileRepositoryProtocol",
    # Supabase contracts
    "SupabaseServiceProtocol"
]
```

### 2. Добавить проверку контрактов в репозитории
```python
# backend/repositories/project_repository.py (ДОБАВИТЬ)
from backend.contracts import ProjectRepositoryProtocol
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.contracts import ProjectRepositoryProtocol

class ProjectRepository(ProjectRepositoryProtocol):  # Явное наследование
    def __init__(self):
        # Реализация
        pass
```

### 3. Создать Contract Validator
```python
# backend/core/contract_validator.py (СОЗДАТЬ)
from typing import Protocol, Type, get_type_hints
import inspect

class ContractValidator:
    @staticmethod
    def validate_implementation(protocol: Type[Protocol], implementation: Type) -> bool:
        """Проверяет соответствие реализации протоколу"""
        protocol_methods = {
            name for name, method in inspect.getmembers(protocol, predicate=inspect.isfunction)
            if not name.startswith('_')
        }
        
        implementation_methods = {
            name for name, method in inspect.getmembers(implementation, predicate=inspect.isfunction)
            if not name.startswith('_')
        }
        
        missing_methods = protocol_methods - implementation_methods
        if missing_methods:
            raise ContractViolationError(f"Missing methods: {missing_methods}")
        
        return True
```

## Последствия
### Положительные:
- ✅ Compile-time проверка контрактов
- ✅ Легкая замена реализаций
- ✅ Соблюдение принципов SOLID
- ✅ Улучшенная тестируемость

### Отрицательные:
- ⚠️ Дополнительная сложность
- ⚠️ Необходимость рефакторинга существующего кода

## Миграция
1. **Фаза 1**: Исправить __init__.py в contracts
2. **Фаза 2**: Добавить явное наследование в репозитории
3. **Фаза 3**: Создать Contract Validator
4. **Фаза 4**: Добавить проверки в тесты

**Время реализации**: 2 дня
**Обратная совместимость**: 100% сохранена