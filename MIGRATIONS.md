# Руководство по миграциям базы данных

> Полное руководство по работе с Alembic миграциями в Samokoder

## 📋 Содержание

- [Введение](#введение)
- [Быстрый старт](#быстрый-старт)
- [Конфигурация](#конфигурация)
- [Применение миграций](#применение-миграций)
- [Создание миграций](#создание-миграций)
- [Откат миграций](#откат-миграций)
- [Продвинутые сценарии](#продвинутые-сценарии)
- [Решение проблем](#решение-проблем)
- [Ссылки на код](#ссылки-на-код)

---

## Введение

Samokoder использует **Alembic** для управления миграциями базы данных.

**Основные концепции:**
- Миграции хранятся в [`alembic/versions/`](alembic/versions/)
- Конфигурация в [`alembic.ini`](alembic.ini)
- Логика миграций в [`alembic/env.py`](alembic/env.py)
- Модели БД в [`core/db/models/`](core/db/models/)

**Поддерживаемые БД:**
- PostgreSQL (production) - `postgresql+asyncpg://...`
- SQLite (development) - `sqlite+aiosqlite://...`

---

## Быстрый старт

### Production (Docker)

```bash
# Применить все миграции
docker-compose exec api alembic upgrade head

# Проверить текущую версию
docker-compose exec api alembic current

# Просмотреть историю
docker-compose exec api alembic history
```

### Development

```bash
# Активировать окружение
poetry shell

# Применить все миграции
alembic upgrade head

# Проверить текущую версию
alembic current

# Просмотреть историю
alembic history --verbose
```

---

## Конфигурация

### Файлы конфигурации

#### alembic.ini

**Файл:** [`alembic.ini`](alembic.ini)

**Ключевые параметры:**

```ini
# Путь к директории миграций
script_location = %(here)s/alembic

# URL базы данных по умолчанию (для SQLite)
sqlalchemy.url = sqlite+aiosqlite:///data/database/samokoder.db
```

**⚠️ Важно:** URL в `alembic.ini` переопределяется переменной окружения `SAMOKODER_DATABASE_URL`

#### alembic/env.py

**Файл:** [`alembic/env.py`](alembic/env.py)

**Логика чтения DATABASE_URL:**

```python
# alembic/env.py:59
url = os.environ.get("SAMOKODER_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
```

**Приоритет:**
1. Переменная окружения `SAMOKODER_DATABASE_URL`
2. `sqlalchemy.url` из `alembic.ini`

### Переменные окружения

#### SAMOKODER_DATABASE_URL

**Описание:** URL базы данных для миграций  
**Требования:** Формат `postgresql+asyncpg://...` или `sqlite+aiosqlite://...`  
**Источник:** [`alembic/env.py:59`](alembic/env.py#L59), [`alembic/env.py:82`](alembic/env.py#L82)

**Примеры:**

```bash
# PostgreSQL (production)
export SAMOKODER_DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/samokoder

# SQLite (development)
export SAMOKODER_DATABASE_URL=sqlite+aiosqlite:///data/database/samokoder.db

# Docker Compose
export SAMOKODER_DATABASE_URL=postgresql+asyncpg://user:password@db:5432/samokoder
```

**Альтернатива:** Добавить в `.env` файл

```bash
# .env
SAMOKODER_DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/samokoder
```

---

## Применение миграций

### Применить все миграции (upgrade)

```bash
# До последней версии
alembic upgrade head

# До конкретной ревизии
alembic upgrade abc123

# На одну миграцию вперед
alembic upgrade +1

# На 2 миграции вперед
alembic upgrade +2
```

**Docker:**
```bash
docker-compose exec api alembic upgrade head
```

### Проверка текущей версии

```bash
# Короткая информация
alembic current

# Детальная информация
alembic current --verbose
```

**Пример вывода:**
```
abc123def456 (head)
```

### Просмотр истории миграций

```bash
# Вся история
alembic history

# С диапазоном
alembic history -r abc123:head

# С подробностями
alembic history --verbose
```

**Пример вывода:**
```
abc123def456 -> 789ghi012jkl (head), add user authentication
456def789ghi -> abc123def456, initial tables
<base> -> 456def789ghi, create database
```

---

## Создание миграций

### Автоматическая генерация (рекомендуется)

Alembic может автоматически обнаружить изменения в моделях:

```bash
# Сгенерировать миграцию на основе изменений моделей
alembic revision --autogenerate -m "description of changes"
```

**Пример:**
```bash
alembic revision --autogenerate -m "add email verification fields"
```

**Что происходит:**
1. Alembic сравнивает модели в [`core/db/models/`](core/db/models/) с текущей схемой БД
2. Генерирует файл миграции в [`alembic/versions/`](alembic/versions/)
3. Файл содержит функции `upgrade()` и `downgrade()`

**⚠️ Важно:** Всегда проверяйте сгенерированную миграцию вручную!

### Ручное создание миграции

Если нужна сложная миграция (например, миграция данных):

```bash
# Создать пустую миграцию
alembic revision -m "migrate user data"
```

**Пример миграции:**

```python
# alembic/versions/abc123_migrate_user_data.py
from alembic import op
import sqlalchemy as sa

revision = 'abc123def456'
down_revision = '456def789ghi'

def upgrade():
    # Добавить колонку
    op.add_column('users', sa.Column('email_verified', sa.Boolean(), default=False))
    
    # Мигрировать данные
    op.execute("UPDATE users SET email_verified = false WHERE email_verified IS NULL")

def downgrade():
    # Откатить изменения
    op.drop_column('users', 'email_verified')
```

### Модели базы данных

**Директория:** [`core/db/models/`](core/db/models/)

**Основные модели:**
- [`user.py`](core/db/models/user.py) - Пользователи
- [`project.py`](core/db/models/project.py) - Проекты
- [`branch.py`](core/db/models/branch.py) - Git ветки
- [`project_state.py`](core/db/models/project_state.py) - Состояние генерации
- [`file.py`](core/db/models/file.py) - Файлы проекта
- [`file_content.py`](core/db/models/file_content.py) - Содержимое файлов
- [`specification.py`](core/db/models/specification.py) - Спецификации
- [`user_input.py`](core/db/models/user_input.py) - Пользовательский ввод
- [`exec_log.py`](core/db/models/exec_log.py) - Логи выполнения

**Импорты в env.py:**

```python
# alembic/env.py:27-36
from samokoder.core.db.models.user import User
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.branch import Branch
from samokoder.core.db.models.project_state import ProjectState
from samokoder.core.db.models.specification import Specification
from samokoder.core.db.models.user_input import UserInput
from samokoder.core.db.models.file import File
from samokoder.core.db.models.file_content import FileContent
from samokoder.core.db.models.exec_log import ExecLog
```

---

## Откат миграций

### Откат на одну версию назад

```bash
alembic downgrade -1
```

### Откат на конкретную версию

```bash
# До ревизии abc123
alembic downgrade abc123

# До базовой версии (пустая БД)
alembic downgrade base
```

### Откат всех миграций

```bash
# ⚠️ ВНИМАНИЕ: Удалит все таблицы!
alembic downgrade base
```

**Docker:**
```bash
docker-compose exec api alembic downgrade -1
```

---

## Продвинутые сценарии

### Несколько баз данных

Если используете несколько БД (например, основная + аналитика):

```bash
# Указать конкретный URL
SAMOKODER_DATABASE_URL=postgresql://user:pass@host/analytics alembic upgrade head
```

### Проверка миграций перед применением

```bash
# Показать SQL без применения
alembic upgrade head --sql > migration.sql

# Просмотреть файл
cat migration.sql
```

### Разрешение конфликтов миграций

Если две ветки создали миграции параллельно:

```bash
# 1. Определить конфликтующие ревизии
alembic heads

# 2. Объединить ветки миграций
alembic merge <rev1> <rev2> -m "merge branches"

# 3. Применить
alembic upgrade head
```

### Миграция данных при смене структуры

**Пример:** Перенос данных из старой колонки в новую

```python
def upgrade():
    # 1. Создать новую колонку
    op.add_column('users', sa.Column('full_name', sa.String(255)))
    
    # 2. Мигрировать данные
    connection = op.get_bind()
    connection.execute(
        "UPDATE users SET full_name = first_name || ' ' || last_name"
    )
    
    # 3. Удалить старые колонки
    op.drop_column('users', 'first_name')
    op.drop_column('users', 'last_name')

def downgrade():
    # Обратная операция
    op.add_column('users', sa.Column('first_name', sa.String(100)))
    op.add_column('users', sa.Column('last_name', sa.String(100)))
    
    connection = op.get_bind()
    # Простое разделение по пробелу (упрощенно)
    connection.execute("""
        UPDATE users 
        SET first_name = SPLIT_PART(full_name, ' ', 1),
            last_name = SPLIT_PART(full_name, ' ', 2)
    """)
    
    op.drop_column('users', 'full_name')
```

---

## Решение проблем

### Проблема: "Can't locate revision identified by 'abc123'"

**Причина:** Миграция отсутствует в `alembic/versions/`

**Решение:**
```bash
# 1. Проверить доступные миграции
ls alembic/versions/

# 2. Если миграция в другой ветке - переключиться
git checkout main

# 3. Или создать новую миграцию с этой базой
alembic stamp head
```

### Проблема: "Target database is not up to date"

**Причина:** БД на устаревшей версии

**Решение:**
```bash
# Применить все миграции
alembic upgrade head
```

### Проблема: "Can't connect to database"

**Причина:** Неверный `SAMOKODER_DATABASE_URL` или БД не запущена

**Решение:**
```bash
# 1. Проверить переменную
echo $SAMOKODER_DATABASE_URL

# 2. Проверить подключение к PostgreSQL
psql -h localhost -U user -d samokoder

# 3. Или запустить через Docker
docker-compose up -d db
```

### Проблема: "Multiple heads detected"

**Причина:** Несколько параллельных веток миграций

**Решение:**
```bash
# 1. Посмотреть heads
alembic heads

# 2. Объединить
alembic merge <head1> <head2> -m "merge migrations"

# 3. Применить
alembic upgrade head
```

### Проблема: "downgrade() не работает"

**Причина:** Функция `downgrade()` не реализована или неполная

**Решение:**
```bash
# 1. Проверить файл миграции
cat alembic/versions/<revision>.py

# 2. Реализовать downgrade() вручную
# 3. Или откатиться до предыдущей версии
alembic downgrade -1
```

### Проблема: Миграция применилась, но схема не изменилась

**Причина:** Миграция выполнена, но произошла ошибка

**Решение:**
```bash
# 1. Проверить логи
alembic upgrade head --verbose

# 2. Откатиться
alembic downgrade -1

# 3. Исправить миграцию
nano alembic/versions/<revision>.py

# 4. Применить заново
alembic upgrade head
```

---

## Ссылки на код

### Конфигурация
- **[alembic.ini](alembic.ini)** - Основная конфигурация Alembic
- **[alembic/env.py](alembic/env.py)** - Логика запуска миграций
- **[alembic/script.py.mako](alembic/script.py.mako)** - Шаблон новых миграций

### Модели
- **[core/db/models/base.py](core/db/models/base.py)** - Базовая модель
- **[core/db/models/user.py](core/db/models/user.py)** - Модель пользователя
- **[core/db/models/](core/db/models/)** - Все модели БД

### Миграции
- **[alembic/versions/](alembic/versions/)** - Директория с миграциями

### Документация
- **[QUICK_START.md](QUICK_START.md)** - Быстрый старт (включая миграции)
- **[ENV_REFERENCE.md](ENV_REFERENCE.md)** - Справочник переменных окружения
- **[README.md](README.md)** - Основная документация

---

## Best Practices

### ✅ Рекомендации

1. **Всегда создавайте downgrade()** - Даже если "никогда не откатим"
2. **Проверяйте автогенерацию** - Alembic может ошибиться
3. **Тестируйте миграции** - Применяйте на тестовой БД перед production
4. **Используйте транзакции** - Миграции должны быть атомарными
5. **Документируйте сложные миграции** - Добавляйте комментарии

### ❌ Чего избегать

1. **Не редактируйте примененные миграции** - Создавайте новые
2. **Не удаляйте файлы миграций** - Даже если откатились
3. **Не забывайте про индексы** - При добавлении колонок
4. **Не делайте большие миграции данных** - Используйте батчинг
5. **Не применяйте миграции вручную** - Используйте Alembic

### Пример "хорошей" миграции

```python
"""Add email verification

Revision ID: abc123def456
Revises: 456def789ghi
Create Date: 2025-10-06 12:00:00

"""
from alembic import op
import sqlalchemy as sa

revision = 'abc123def456'
down_revision = '456def789ghi'
branch_labels = None
depends_on = None

def upgrade():
    # Добавить колонку с дефолтным значением
    op.add_column('users', 
        sa.Column('email_verified', sa.Boolean(), 
                  nullable=False, server_default='false')
    )
    
    # Создать индекс
    op.create_index(
        'ix_users_email_verified', 
        'users', 
        ['email_verified']
    )
    
    # Мигрировать существующие данные
    op.execute("""
        UPDATE users 
        SET email_verified = true 
        WHERE created_at < '2025-01-01'
    """)

def downgrade():
    # Удалить индекс
    op.drop_index('ix_users_email_verified', table_name='users')
    
    # Удалить колонку
    op.drop_column('users', 'email_verified')
```

---

## Дополнительные ресурсы

- **Официальная документация Alembic:** https://alembic.sqlalchemy.org/
- **SQLAlchemy документация:** https://docs.sqlalchemy.org/
- **Примеры миграций:** [`alembic/versions/`](alembic/versions/)
