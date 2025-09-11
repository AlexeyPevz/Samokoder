# ADR-001: Нарушение границ модулей в API слое

## Статус
**ПРИНЯТО** - 2025-01-11

## Контекст
Аудит архитектуры выявил критические нарушения принципов модульности в API слое:

### Обнаруженные проблемы:
- **backend/api/projects.py:5-6** - 13 внутренних зависимостей
- **backend/api/ai.py:6-7** - 9 внутренних зависимостей  
- **backend/api/health.py:7-8** - 12 внутренних зависимостей
- **backend/api/file_upload.py:10-12** - 13 внутренних зависимостей
- **backend/api/auth.py:7-8** - 11 внутренних зависимостей
- **backend/api/api_keys.py:7-9** - 13 внутренних зависимостей

### Риски:
1. **Циклические зависимости** - высокая вероятность
2. **Нарушение принципа единственной ответственности**
3. **Сложность тестирования** - модули тесно связаны
4. **Нарушение отказоустойчивости** - падение одного модуля влияет на многие

## Решение
Внедрить **Facade Pattern** для API модулей с минимальными изменениями:

### 1. Создать API Facade
```python
# backend/api/facades/project_facade.py
class ProjectAPIFacade:
    def __init__(self):
        self._project_service = None  # Lazy loading
        self._auth_service = None     # Lazy loading
    
    @property
    def project_service(self):
        if not self._project_service:
            self._project_service = ProjectService()
        return self._project_service
```

### 2. Рефакторинг API модулей
```python
# backend/api/projects.py (ПОСЛЕ)
from backend.api.facades.project_facade import ProjectAPIFacade

router = APIRouter()
facade = ProjectAPIFacade()

@router.post("/")
async def create_project(request: ProjectCreateRequest):
    return await facade.project_service.create(request)
```

## Последствия
### Положительные:
- ✅ Снижение связанности модулей
- ✅ Улучшение тестируемости
- ✅ Повышение отказоустойчивости
- ✅ Сохранение публичных контрактов

### Отрицательные:
- ⚠️ Небольшое увеличение сложности
- ⚠️ Дополнительный слой абстракции

## Миграция
1. **Фаза 1**: Создать facades без изменения API
2. **Фаза 2**: Постепенно переносить логику в facades
3. **Фаза 3**: Удалить прямые зависимости

**Время реализации**: 2-3 дня
**Обратная совместимость**: 100% сохранена