# 🗄️ Миграции базы данных - Самокодер v1.0.0

> **Руководство по управлению миграциями базы данных**  
> Для разработчиков и DevOps инженеров

## 📋 Содержание

- [Обзор миграций](#-обзор-миграций)
- [Настройка Alembic](#-настройка-alembic)
- [Создание миграций](#-создание-миграций)
- [Применение миграций](#-применение-миграций)
- [Откат миграций](#-откат-миграций)
- [Устранение проблем](#-устранение-проблем)
- [Best Practices](#-best-practices)

## 🎯 Обзор миграций

### 📊 Что такое миграции?

Миграции базы данных — это версионированные изменения схемы БД, которые позволяют:
- **Безопасно изменять структуру** базы данных
- **Отслеживать историю изменений** схемы
- **Синхронизировать изменения** между окружениями
- **Откатывать изменения** при необходимости

### 🏗️ Архитектура миграций

```
database/
├── migrations/
│   ├── env.py              # Конфигурация Alembic
│   ├── script.py.mako      # Шаблон миграций
│   └── versions/           # Файлы миграций
│       ├── 001_initial_schema.py
│       ├── 002_add_users_table.py
│       └── 003_add_projects_table.py
├── schema.sql              # Текущая схема БД
└── alembic.ini             # Конфигурация Alembic
```

## ⚙️ Настройка Alembic

### 🔧 Инициализация

```bash
# Установите Alembic
pip install alembic

# Инициализируйте Alembic в проекте
alembic init database/migrations

# Это создаст:
# - alembic.ini (конфигурация)
# - database/migrations/ (директория миграций)
# - database/migrations/env.py (конфигурация окружения)
```

### 📝 Конфигурация alembic.ini

```ini
# alembic.ini
[alembic]
# Путь к директории миграций
script_location = database/migrations

# URL базы данных (будет переопределен в env.py)
sqlalchemy.url = postgresql://user:pass@localhost/dbname

# Шаблон для именования файлов миграций
file_template = %%(year)d%%(month).2d%%(day).2d_%%(hour).2d%%(minute).2d_%%(rev)s_%%(slug)s

# Логирование
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

### 🔧 Конфигурация env.py

```python
# database/migrations/env.py
import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context

# Добавьте путь к проекту
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Импортируйте модели
from backend.models.database import Base
from config.settings import settings

# Конфигурация Alembic
config = context.config

# Настройте URL базы данных
config.set_main_option("sqlalchemy.url", settings.database_url)

# Настройте целевые метаданные
target_metadata = Base.metadata

# Настройте логирование
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

def run_migrations_offline():
    """Запуск миграций в 'offline' режиме."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Запуск миграций в 'online' режиме."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

## 📝 Создание миграций

### 🆕 Автоматическое создание

```bash
# Создайте миграцию на основе изменений в моделях
python -m alembic revision --autogenerate -m "Add users table"

# Это создаст файл в database/migrations/versions/
# Например: 20250910_120000_abc123_add_users_table.py
```

### ✏️ Ручное создание

```bash
# Создайте пустую миграцию
python -m alembic revision -m "Custom migration"

# Отредактируйте созданный файл
# database/migrations/versions/20250910_120000_def456_custom_migration.py
```

### 📄 Структура файла миграции

```python
# database/migrations/versions/20250910_120000_abc123_add_users_table.py
"""Add users table

Revision ID: abc123
Revises: 
Create Date: 2025-09-10 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = 'abc123'
down_revision = None  # или ID предыдущей миграции
branch_labels = None
depends_on = None

def upgrade():
    """Применение миграции."""
    # Создание таблицы users
    op.create_table('users',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Создание индекса
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

def downgrade():
    """Откат миграции."""
    # Удаление индекса
    op.drop_index('ix_users_email', table_name='users')
    
    # Удаление таблицы
    op.drop_table('users')
```

### 🔧 Типичные операции миграций

#### Создание таблицы
```python
def upgrade():
    op.create_table('projects',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('projects')
```

#### Добавление колонки
```python
def upgrade():
    op.add_column('users', sa.Column('full_name', sa.String(length=255), nullable=True))

def downgrade():
    op.drop_column('users', 'full_name')
```

#### Изменение типа колонки
```python
def upgrade():
    op.alter_column('users', 'email',
                    existing_type=sa.VARCHAR(length=100),
                    type_=sa.VARCHAR(length=255),
                    existing_nullable=False)

def downgrade():
    op.alter_column('users', 'email',
                    existing_type=sa.VARCHAR(length=255),
                    type_=sa.VARCHAR(length=100),
                    existing_nullable=False)
```

#### Создание индекса
```python
def upgrade():
    op.create_index('ix_projects_user_id', 'projects', ['user_id'])

def downgrade():
    op.drop_index('ix_projects_user_id', table_name='projects')
```

#### Добавление внешнего ключа
```python
def upgrade():
    op.create_foreign_key('fk_projects_user_id', 'projects', 'users', ['user_id'], ['id'])

def downgrade():
    op.drop_constraint('fk_projects_user_id', 'projects', type_='foreignkey')
```

## 🚀 Применение миграций

### 📊 Просмотр статуса

```bash
# Просмотр текущей версии
python -m alembic current

# Просмотр истории миграций
python -m alembic history

# Просмотр истории с ветками
python -m alembic history --verbose

# Просмотр следующей миграции
python -m alembic next

# Просмотр предыдущей миграции
python -m alembic prev
```

### ⬆️ Применение миграций

```bash
# Применение всех миграций до последней
python -m alembic upgrade head

# Применение до конкретной версии
python -m alembic upgrade abc123

# Применение на одну миграцию вперед
python -m alembic upgrade +1

# Применение на несколько миграций
python -m alembic upgrade +3
```

### 🔍 Проверка миграций

```bash
# Просмотр SQL команд без выполнения
python -m alembic upgrade head --sql

# Просмотр SQL для конкретной миграции
python -m alembic upgrade abc123 --sql
```

## ⬇️ Откат миграций

### 🔄 Откат миграций

```bash
# Откат на одну миграцию назад
python -m alembic downgrade -1

# Откат до конкретной версии
python -m alembic downgrade abc123

# Откат всех миграций
python -m alembic downgrade base

# Откат на несколько миграций
python -m alembic downgrade -3
```

### ⚠️ Откат с данными

```python
# database/migrations/versions/20250910_120000_abc123_add_users_table.py
def upgrade():
    # Создание таблицы
    op.create_table('users', ...)
    
    # Миграция данных из старой таблицы
    connection = op.get_bind()
    connection.execute("""
        INSERT INTO users (id, email, password_hash, created_at, updated_at)
        SELECT id, email, password, created_at, updated_at
        FROM old_users
    """)

def downgrade():
    # Сохранение данных перед удалением
    connection = op.get_bind()
    connection.execute("""
        CREATE TABLE old_users AS 
        SELECT * FROM users
    """)
    
    # Удаление таблицы
    op.drop_table('users')
```

## 🐛 Устранение проблем

### ❌ Общие проблемы

#### "Target database is not up to date"
```bash
# Проблема: База данных не синхронизирована
# Решение: Примените все миграции
python -m alembic upgrade head
```

#### "Can't locate revision identified by 'abc123'"
```bash
# Проблема: Миграция не найдена
# Решение: Проверьте историю миграций
python -m alembic history

# Или сбросьте до известной версии
python -m alembic stamp head
```

#### "Multiple heads detected"
```bash
# Проблема: Несколько головных миграций
# Решение: Создайте merge миграцию
python -m alembic merge -m "Merge heads" head1 head2
```

#### "Working directory is not clean"
```bash
# Проблема: Незакоммиченные изменения
# Решение: Закоммитьте изменения или отмените их
git add .
git commit -m "WIP: migration changes"
# или
git stash
```

### 🔧 Продвинутое устранение проблем

#### Сброс миграций
```bash
# ОСТОРОЖНО: Это удалит все данные!
# 1. Создайте бэкап
pg_dump -h localhost -U samokoder -d samokoder > backup.sql

# 2. Удалите все таблицы
psql -h localhost -U samokoder -d samokoder -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# 3. Сбросьте версию Alembic
python -m alembic stamp base

# 4. Примените все миграции
python -m alembic upgrade head
```

#### Исправление сломанной миграции
```bash
# 1. Откатите до предыдущей миграции
python -m alembic downgrade -1

# 2. Отредактируйте сломанную миграцию
# database/migrations/versions/broken_migration.py

# 3. Примените исправленную миграцию
python -m alembic upgrade head
```

#### Восстановление после сбоя
```bash
# 1. Проверьте текущий статус
python -m alembic current

# 2. Проверьте, какие миграции применены
python -m alembic history --verbose

# 3. Примените недостающие миграции
python -m alembic upgrade head
```

## 📋 Best Practices

### ✅ Рекомендации по созданию миграций

#### 1. Всегда создавайте откат
```python
def upgrade():
    op.add_column('users', sa.Column('phone', sa.String(20), nullable=True))

def downgrade():
    op.drop_column('users', 'phone')  # Всегда добавляйте откат!
```

#### 2. Используйте транзакции для больших изменений
```python
def upgrade():
    # Большие изменения в транзакции
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('new_field', sa.String(255)))
        batch_op.create_index('ix_users_new_field', ['new_field'])
```

#### 3. Проверяйте существование объектов
```python
def upgrade():
    # Проверьте, существует ли таблица
    if not op.get_bind().dialect.has_table(op.get_bind(), 'users'):
        op.create_table('users', ...)
```

#### 4. Используйте условные операции
```python
def upgrade():
    # Добавьте колонку только если её нет
    if not op.get_bind().dialect.has_column(op.get_bind(), 'users', 'phone'):
        op.add_column('users', sa.Column('phone', sa.String(20)))
```

### ✅ Рекомендации по применению миграций

#### 1. Всегда тестируйте миграции
```bash
# Тестирование на копии БД
createdb samokoder_test
python -m alembic upgrade head --sql > test_migration.sql
psql samokoder_test < test_migration.sql
```

#### 2. Создавайте бэкапы
```bash
# Перед применением миграций
pg_dump -h localhost -U samokoder -d samokoder > backup_$(date +%Y%m%d_%H%M%S).sql
```

#### 3. Применяйте миграции поэтапно
```bash
# Не применяйте все миграции сразу в продакшене
python -m alembic upgrade +1  # По одной миграции
```

#### 4. Мониторьте производительность
```bash
# Включите логирование медленных запросов
psql -c "ALTER SYSTEM SET log_min_duration_statement = 1000;"
psql -c "SELECT pg_reload_conf();"
```

### ✅ Рекомендации по откату

#### 1. Планируйте откат заранее
```python
def upgrade():
    # Сохраните данные перед изменением
    op.execute("CREATE TABLE users_backup AS SELECT * FROM users")
    
    # Выполните изменения
    op.alter_column('users', 'email', type_=sa.String(255))

def downgrade():
    # Восстановите данные
    op.execute("UPDATE users SET email = (SELECT email FROM users_backup WHERE users.id = users_backup.id)")
    op.drop_table('users_backup')
```

#### 2. Тестируйте откат
```bash
# Тестирование отката
python -m alembic downgrade -1
python -m alembic upgrade +1
```

## 🚀 Автоматизация миграций

### 📜 Скрипты для CI/CD

#### GitHub Actions
```yaml
# .github/workflows/migrations.yml
name: Database Migrations

on:
  push:
    branches: [main]
    paths: ['database/migrations/**']

jobs:
  migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          
      - name: Run migrations
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: |
          python -m alembic upgrade head
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  migrate:
    image: samokoder/backend:latest
    command: python -m alembic upgrade head
    environment:
      - DATABASE_URL=${DATABASE_URL}
    depends_on:
      - postgres
    restart: "no"
```

### 🔧 Утилиты для разработки

#### Скрипт проверки миграций
```bash
#!/bin/bash
# scripts/check_migrations.sh

echo "🔍 Проверка миграций..."

# Проверьте, есть ли непримененные миграции
UNAPPLIED=$(python -m alembic current 2>&1 | grep -c "Target database is not up to date" || true)

if [ "$UNAPPLIED" -gt 0 ]; then
    echo "❌ Есть непримененные миграции"
    python -m alembic history --verbose
    exit 1
else
    echo "✅ Все миграции применены"
fi

# Проверьте, есть ли новые миграции
NEW_MIGRATIONS=$(python -m alembic heads | wc -l)
if [ "$NEW_MIGRATIONS" -gt 1 ]; then
    echo "⚠️  Обнаружены множественные головы миграций"
    python -m alembic heads
    exit 1
fi

echo "✅ Миграции в порядке"
```

#### Скрипт создания миграции
```bash
#!/bin/bash
# scripts/create_migration.sh

if [ -z "$1" ]; then
    echo "Использование: $0 <описание_миграции>"
    exit 1
fi

DESCRIPTION="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "📝 Создание миграции: $DESCRIPTION"

# Создайте миграцию
python -m alembic revision --autogenerate -m "$DESCRIPTION"

# Получите имя файла
MIGRATION_FILE=$(ls -t database/migrations/versions/ | head -n1)

echo "✅ Миграция создана: $MIGRATION_FILE"
echo "📝 Отредактируйте файл при необходимости"
echo "🚀 Примените миграцию: python -m alembic upgrade head"
```

---

## 🎯 Чек-лист миграций

### ✅ Перед созданием миграции
- [ ] Создайте бэкап базы данных
- [ ] Протестируйте изменения на копии БД
- [ ] Убедитесь, что все модели синхронизированы
- [ ] Проверьте, что нет конфликтующих изменений

### ✅ При создании миграции
- [ ] Используйте описательные имена
- [ ] Всегда создавайте функцию downgrade
- [ ] Проверьте существование объектов
- [ ] Используйте транзакции для больших изменений
- [ ] Добавьте комментарии к сложным операциям

### ✅ Перед применением миграции
- [ ] Создайте бэкап продакшена
- [ ] Протестируйте миграцию на staging
- [ ] Проверьте производительность
- [ ] Уведомите команду о плановых работах

### ✅ После применения миграции
- [ ] Проверьте целостность данных
- [ ] Проверьте производительность
- [ ] Убедитесь, что приложение работает
- [ ] Обновите документацию

---

**Создано с ❤️ командой Самокодер**  
**© 2025 Samokoder. Все права защищены.**