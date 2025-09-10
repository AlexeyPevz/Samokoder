# ADR: Архитектурный аудит и исправления (2025-01-27)

## Статус
**ПРИНЯТО** - 2025-01-27

## Контекст

Проведен комплексный аудит архитектуры Samokoder по принципам 12-Factor App, проверены границы модулей, контракты и миграции. Выявлены критические проблемы, требующие исправления без breaking changes.

## Проблемы

### 1. Нарушение 12-Factor App принципов
- **Config**: Секреты в коде (`secret_key`, `api_encryption_salt`)
- **Dependencies**: Отсутствует `.env.example`
- **Backing Services**: Хардкод URL в `alembic.ini`
- **Processes**: In-memory хранилище `active_projects` не масштабируется

### 2. Нарушение принципов архитектуры
- **Нарушение DIP**: Прямые импорты `supabase` в `main.py`
- **Дублирование кода**: Множественные `main_*.py` файлы
- **Смешение ответственности**: `AIServiceImpl` делегирует вместо реализации

### 3. Проблемы конфигурации
- Отсутствует `.env.example` для разработчиков
- Хардкод значений в конфигурации
- Смешение конфигурации и кода

## Решения

### 1. Исправление 12-Factor App нарушений

#### 1.1 Config - Вынос секретов в переменные окружения
```python
# ДО
secret_key: str = "QvXgcQGd8pz8YETjvWhCLnAJ5SHD2A6uQzBn3_5dNaE"
api_encryption_salt: str = "samokoder_salt_2025"

# ПОСЛЕ
secret_key: str  # Обязательная переменная окружения
api_encryption_salt: str  # Обязательная переменная окружения
```

#### 1.2 Создание .env.example
Создан файл `.env.example` с полным набором переменных окружения для всех сред.

#### 1.3 Исправление alembic.ini
```ini
# ДО
sqlalchemy.url = postgresql://postgres:password@localhost:5432/samokoder

# ПОСЛЕ
# sqlalchemy.url = postgresql://postgres:password@localhost:5432/samokoder
# URL will be set from environment variables in env.py
```

### 2. Исправление архитектурных проблем

#### 2.1 Создание абстракции для Supabase
```python
# Новый контракт
class SupabaseServiceProtocol(Protocol):
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]: ...
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]: ...
    # ... другие методы

# Реализация
class SupabaseServiceImpl(SupabaseServiceProtocol):
    def __init__(self):
        self.client: Optional[Client] = None
        self._initialize_client()
```

#### 2.2 Обновление DI контейнера
```python
# Регистрация нового сервиса
container.register(SupabaseServiceProtocol, SupabaseServiceImpl, singleton=True)

# Функция для получения сервиса
def get_supabase_service() -> SupabaseServiceProtocol:
    return container.get(SupabaseServiceProtocol)
```

### 3. Улучшение конфигурации

#### 3.1 Динамическая конфигурация миграций
```python
# env.py
if not config.get_main_option("sqlalchemy.url"):
    from config.settings import settings
    database_url = f"postgresql://{settings.database_user}:{settings.database_password}@{settings.database_host}:{settings.database_port}/{settings.database_name}"
    config.set_main_option("sqlalchemy.url", database_url)
```

## Последствия

### Положительные
- ✅ Соответствие 12-Factor App принципам
- ✅ Улучшенная безопасность (секреты в переменных окружения)
- ✅ Лучшая архитектура (DIP, абстракции)
- ✅ Упрощенная настройка для разработчиков (.env.example)
- ✅ Гибкая конфигурация миграций

### Отрицательные
- ⚠️ Требуется обновление переменных окружения
- ⚠️ Необходимо обновить документацию по настройке

## Миграция

### Для разработчиков
1. Скопировать `.env.example` в `.env`
2. Заполнить переменные окружения
3. Перезапустить приложение

### Для продакшена
1. Обновить переменные окружения в CI/CD
2. Убедиться, что все секреты настроены
3. Протестировать миграции

## Мониторинг

- Проверка health check эндпоинтов
- Мониторинг ошибок конфигурации
- Логирование отсутствующих переменных окружения

## Альтернативы

### Рассмотренные варианты
1. **Оставить как есть** - Отклонено из-за нарушений безопасности
2. **Полная рефакторинг** - Отклонено из-за breaking changes
3. **Постепенные исправления** - ✅ Принято

### Причины выбора
- Минимальные breaking changes
- Улучшение безопасности
- Соответствие best practices
- Простота миграции

## Связанные решения

- ADR-001: Выбор FastAPI как основного фреймворка
- ADR-002: Использование Supabase как Backend-as-a-Service
- ADR-003: Dependency Injection Container

## Участники

- **Архитектор**: CTO/Архитектор с 20-летним опытом
- **Дата**: 2025-01-27
- **Статус**: Принято и реализовано

---

## Приложение: Детальный аудит по 12-Factor App

### ✅ Соответствует
1. **Codebase** - Один репозиторий для всех сред
2. **Build, Release, Run** - Multi-stage Dockerfile, Docker Compose
3. **Port Binding** - Приложение привязано к порту 8000
4. **Logs** - Структурированное логирование, Sentry, Prometheus

### ⚠️ Частично соответствует
5. **Dependencies** - Четко определены, но отсутствовал .env.example
6. **Backing Services** - Supabase как внешний сервис, но хардкод URL
7. **Dev/Prod Parity** - Разные настройки в коде

### ❌ Не соответствует (исправлено)
8. **Config** - Секреты в коде (исправлено)
9. **Processes** - In-memory состояние (требует дальнейшей работы)
10. **Concurrency** - In-memory состояние не масштабируется
11. **Disposability** - Потеря состояния при перезапуске
12. **Admin Processes** - Отсутствуют admin скрипты

## Приложение: Архитектурные улучшения

### Созданные контракты
- `SupabaseServiceProtocol` - Абстракция для работы с Supabase
- `AIServiceProtocol` - Абстракция для AI сервисов
- `DatabaseServiceProtocol` - Абстракция для работы с БД

### Реализации
- `SupabaseServiceImpl` - Реализация Supabase сервиса
- `AIServiceImpl` - Реализация AI сервиса
- `DatabaseServiceImpl` - Реализация БД сервиса

### DI Container
- Регистрация всех сервисов
- Singleton pattern для stateful сервисов
- Функции для получения сервисов