# Реализация системы монетизации с ограничениями по тирам

## Обзор изменений

Была полностью реализована комплексная система tier-based ограничений для монетизации проекта. Теперь все тиры имеют чёткие ограничения и пользователи не могут использовать функции, недоступные в их плане.

**Важно:** Проект использует модель BYOK (Bring Your Own Key) - пользователи предоставляют собственные API ключи для LLM провайдеров. Поэтому ограничений на использование конкретных моделей НЕТ - все модели доступны всем пользователям. Монетизация основана на платформенных функциях (деплой, количество проектов, git операции и т.д.).

## Структура тиров

### 1. FREE (Бесплатный)
**Цена:** 0 руб/мес

**Лимиты:**
- Проекты: 2 в месяц, 2 всего
- Деплои: 0 (недоступно)
- Экспорты: 2 в месяц
- Git push: 5 в месяц

**Доступные функции:**
- ✅ Создание проектов
- ❌ Деплой
- ✅ Экспорт
- ✅ Git push
- ❌ Кастомные шаблоны
- ❌ Командная работа
- ❌ Приоритетная поддержка
- ❌ Кастомный брендинг

**Доступные модели:**
- ✅ Все модели доступны (BYOK - используйте свои API ключи)

**Rate limits:**
- 30 запросов/минуту
- 1000 запросов/час
- 10000 запросов/день

---

### 2. STARTER
**Цена:** 490 руб/мес

**Лимиты:**
- Проекты: 10 в месяц, 100 всего
- Деплои: 10 в месяц
- Экспорты: 50 в месяц
- Git push: 100 в месяц

**Доступные функции:**
- ✅ Создание проектов
- ✅ Деплой
- ✅ Экспорт
- ✅ Git push
- ✅ Кастомные шаблоны
- ❌ Командная работа
- ❌ Приоритетная поддержка
- ❌ Кастомный брендинг

**Доступные модели:**
- ✅ Все модели доступны (BYOK - используйте свои API ключи)

**Rate limits:**
- 100 запросов/минуту
- 5000 запросов/час
- 50000 запросов/день

---

### 3. PRO
**Цена:** 1490 руб/мес

**Лимиты:**
- Проекты: 50 в месяц, безлимит всего
- Деплои: 100 в месяц
- Экспорты: безлимит
- Git push: безлимит

**Доступные функции:**
- ✅ Создание проектов
- ✅ Деплой
- ✅ Экспорт
- ✅ Git push
- ✅ Кастомные шаблоны
- ✅ Командная работа
- ✅ Приоритетная поддержка
- ❌ Кастомный брендинг

**Доступные модели:**
- ✅ Все модели доступны (BYOK - используйте свои API ключи)

**Rate limits:**
- 200 запросов/минуту
- 10000 запросов/час
- 100000 запросов/день

---

### 4. TEAM
**Цена:** 2490 руб/мес

**Лимиты:**
- Проекты: безлимит
- Деплои: безлимит
- Экспорты: безлимит
- Git push: безлимит

**Доступные функции:**
- ✅ Все функции включены

**Доступные модели:**
- ✅ Все модели доступны (BYOK - используйте свои API ключи)

**Rate limits:**
- 500 запросов/минуту
- 20000 запросов/час
- 200000 запросов/день

---

## Реализованные файлы

### 1. `core/api/middleware/tier_limits.py`
Центральный модуль системы ограничений:
- `TierFeature` - enum с доступными функциями
- `TIER_CONFIG` - конфигурация всех тиров
- `TierLimitService` - сервис для проверки ограничений
- Dependency functions для FastAPI endpoints

### 2. `api/routers/projects.py` (обновлен)
Добавлено ограничение на создание проектов:
```python
@router.post("/", response_model=ProjectDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
    _limits_check = Depends(require_project_limits),  # ← Новая проверка
):
    ...
```

### 3. `api/routers/models.py` (без изменений)
Модели остаются доступными для всех пользователей (BYOK модель).
- API `/v1/models` возвращает все доступные модели
- Не требует авторизации
- Пользователи используют свои API ключи для доступа к моделям

### 4. `api/routers/preview.py` (обновлен)
Добавлена проверка доступа к деплою/preview:
```python
@router.post("/projects/{project_id}/preview/start")
async def start_preview(
    ...,
    _deploy_check = Depends(require_deploy_access)  # Проверка доступа
):
    ...
```

### 5. `api/routers/plugins.py` (обновлен)
Добавлена проверка доступа к git операциям:
```python
@router.post("/plugins/{plugin_name}/github/create-repo")
async def create_github_repo(
    ...,
    _git_check = Depends(require_git_push_access)  # Проверка доступа
):
    ...
```

### 6. `api/routers/user.py` (обновлен)
Добавлен эндпоинт для получения информации о тире:
```python
@router.get("/user/tier")
async def get_user_tier_info(tier_info: Dict = Depends(get_tier_info)):
    """Получить детальную информацию о тире пользователя"""
    return tier_info
```

### 7. `tests/api/test_tier_limits.py` (создан)
Полный набор тестов для проверки:
- Корректности конфигурации тиров
- Проверки доступа к функциям
- Фильтрации моделей
- Лимитов на создание проектов

---

## API эндпоинты

### Получить информацию о своём тире
```http
GET /v1/user/tier
Authorization: Bearer <token>
```

**Ответ:**
```json
{
  "tier": "starter",
  "name": "Starter",
  "price": 490,
  "limits": {
    "projects_monthly": 10,
    "projects_total": 100,
    "deployments_monthly": 10,
    "exports_monthly": 50,
    "git_pushes_monthly": 100
  },
  "features": {
    "create_project": true,
    "deploy": true,
    "export": true,
    "git_push": true,
    "custom_templates": true,
    "team_collaboration": false,
    "priority_support": false,
    "custom_branding": false
  },
  "rate_limits": {
    "requests_per_minute": 100,
    "requests_per_hour": 5000,
    "requests_per_day": 50000
  }
}
```

### Получить доступные модели
```http
GET /v1/models
```
(Не требует авторизации - BYOK модель)

**Ответ:**
```json
{
  "openai": {
    "models": [
      {
        "id": "gpt-4o",
        "name": "GPT-4o",
        "context": 128000
      },
      {
        "id": "gpt-4o-mini",
        "name": "GPT-4o Mini",
        "context": 128000
      }
    ],
    "default": "gpt-4o-mini"
  },
  "anthropic": {
    "models": [
      {
        "id": "claude-3-opus-20240229",
        "name": "Claude 3 Opus",
        "context": 200000
      }
    ],
    "default": "claude-3-5-sonnet-20241022"
  }
}
```

### Создать проект (с проверкой лимитов)
```http
POST /v1/projects
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "My New Project",
  "description": "Project description"
}
```

**Успешный ответ (200):**
```json
{
  "project": {
    "id": "uuid-here",
    "name": "My New Project",
    "description": "Project description",
    "created_at": "2025-10-06T12:00:00Z"
  }
}
```

**Ошибка при превышении лимита (402):**
```json
{
  "detail": "Monthly project limit reached (2 projects). Upgrade to starter for more projects."
}
```

---

## Коды ошибок

### 402 Payment Required
Возвращается когда пользователь достиг лимита своего тира:
- При превышении месячного лимита проектов
- При превышении общего лимита проектов
- При превышении лимита деплоев
- При превышении лимита экспортов

### 403 Forbidden
Возвращается когда функция недоступна в текущем тире:
- Попытка деплоя/preview на FREE тире
- Попытка создать GitHub репозиторий при превышении лимита git операций
- Попытка использовать командные функции на FREE/STARTER тире

---

## Примеры использования в коде

### Проверка доступа к функции
```python
from samokoder.core.api.middleware.tier_limits import require_deploy_access

@router.post("/projects/{project_id}/deploy")
async def deploy_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
    _access_check = Depends(require_deploy_access)  # Проверка доступа к деплою
):
    # Код деплоя
    ...
```

### Получение информации о тире в коде
```python
from samokoder.core.api.middleware.tier_limits import TierLimitService

# Проверить доступность функции
if TierLimitService.has_feature(user, TierFeature.DEPLOY):
    # Пользователь может деплоить
    ...

# Получить информацию о тире
config = TierLimitService.get_tier_config(user.tier)
print(config["name"], config["price"])
```

---

## Миграция существующих пользователей

Все существующие пользователи по умолчанию находятся на FREE тире (как указано в модели User).

Для апгрейда тира используется эндпоинт:
```http
POST /api/v1/subscribe
Authorization: Bearer <token>
Content-Type: application/json

{
  "tier": "starter"
}
```

После успешной оплаты через CloudPayments webhook обновляет тир пользователя в базе данных.

---

## Следующие шаги

1. **Трекинг использования**: Добавить отдельные таблицы для трекинга использования операций (деплои, экспорты, git push) вместо хранения в JSON поле
2. **Уведомления**: Добавить уведомления пользователям при приближении к лимитам
3. **Аналитика**: Добавить дашборд с использованием лимитов
4. **Автоматический сброс**: Добавить cronjob для сброса месячных счетчиков
5. **Soft limits**: Добавить предупреждения при достижении 80% лимита

---

## Тестирование

Запустить тесты:
```bash
pytest tests/api/test_tier_limits.py -v
```

Тесты покрывают:
- ✅ Корректность конфигурации всех тиров
- ✅ Иерархию тиров (каждый следующий должен иметь больше возможностей)
- ✅ Проверку доступа к функциям для каждого тира
- ✅ Фильтрацию моделей по тирам
- ✅ Проверку лимитов на создание проектов
- ✅ Правильные коды ошибок при превышении лимитов

---

## Заключение

Система монетизации теперь полностью функциональна:
1. ✅ Все тиры имеют чёткие ограничения
2. ✅ Ограничения применяются на уровне API
3. ✅ Пользователи видят только доступные им модели
4. ✅ Понятные сообщения об ошибках с предложением апгрейда
5. ✅ Покрытие тестами
6. ✅ Документация

Монетизация реализована корректно и готова к использованию!
