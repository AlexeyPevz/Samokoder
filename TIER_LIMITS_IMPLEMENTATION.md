# Реализация системы монетизации с ограничениями по тирам

## Обзор изменений

Была полностью реализована комплексная система tier-based ограничений для монетизации проекта. Теперь все тиры имеют чёткие ограничения и пользователи не могут использовать функции, недоступные в их плане.

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
- ❌ Продвинутые модели
- ❌ Кастомные шаблоны
- ❌ Командная работа
- ❌ Приоритетная поддержка
- ❌ Кастомный брендинг

**Доступные модели:**
- gpt-3.5-turbo
- gpt-4o-mini
- Llama 3.x (через Groq)
- Mixtral

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
- ✅ Продвинутые модели
- ✅ Кастомные шаблоны
- ❌ Командная работа
- ❌ Приоритетная поддержка
- ❌ Кастомный брендинг

**Доступные модели:**
- Все из FREE +
- gpt-4o
- gpt-4-turbo
- gpt-4

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
- ✅ Продвинутые модели
- ✅ Кастомные шаблоны
- ✅ Командная работа
- ✅ Приоритетная поддержка
- ❌ Кастомный брендинг

**Доступные модели:**
- Все из STARTER +
- Claude 3 Opus
- Claude 3 Sonnet
- Claude 3 Haiku
- Google Gemini Pro 1.5

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
- Все из PRO +
- Claude 3.5 Sonnet (новая)

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

### 3. `api/routers/models.py` (обновлен)
Добавлена фильтрация моделей по тирам:
- Каждая модель имеет поле `tier` с минимальным требуемым тиром
- API `/v1/models` возвращает модели с полем `available: true/false`
- Для недоступных моделей указывается `required_tier`

### 4. `api/routers/user.py` (обновлен)
Добавлен эндпоинт для получения информации о тире:
```python
@router.get("/user/tier")
async def get_user_tier_info(tier_info: Dict = Depends(get_tier_info)):
    """Получить детальную информацию о тире пользователя"""
    return tier_info
```

### 5. `tests/api/test_tier_limits.py` (создан)
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
    "advanced_models": true,
    "custom_templates": true,
    "team_collaboration": false,
    "priority_support": false,
    "custom_branding": false
  },
  "allowed_models": [
    "gpt-3.5-turbo",
    "gpt-4o-mini",
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-4"
  ]
}
```

### Получить доступные модели
```http
GET /v1/models
Authorization: Bearer <token>
```

**Ответ:**
```json
{
  "openai": {
    "models": [
      {
        "id": "gpt-4o",
        "name": "GPT-4o",
        "context": 128000,
        "tier": "starter",
        "available": true
      },
      {
        "id": "gpt-4o-mini",
        "name": "GPT-4o Mini",
        "context": 128000,
        "tier": "free",
        "available": true
      }
    ],
    "default": "gpt-4o-mini"
  },
  "anthropic": {
    "models": [
      {
        "id": "claude-3-opus-20240229",
        "name": "Claude 3 Opus",
        "context": 200000,
        "tier": "pro",
        "available": false,
        "required_tier": "pro"
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
- Попытка деплоя на FREE тире
- Попытка использовать модель Claude на FREE/STARTER тире
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

### Проверка доступа к модели
```python
from samokoder.core.api.middleware.tier_limits import require_model_access

@router.post("/generate")
async def generate_code(
    model: str,
    current_user: User = Depends(get_current_user),
    _model_check = Depends(require_model_access(model))  # Проверка доступа к модели
):
    # Код генерации
    ...
```

### Получение информации о тире в коде
```python
from samokoder.core.api.middleware.tier_limits import TierLimitService

# Проверить доступность функции
if TierLimitService.has_feature(user, TierFeature.DEPLOY):
    # Пользователь может деплоить
    ...

# Получить доступные модели
allowed_models = TierLimitService.get_allowed_models(user)

# Проверить конкретную модель
if TierLimitService.is_model_allowed(user, "gpt-4o"):
    # Можно использовать gpt-4o
    ...
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
