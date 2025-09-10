# ADR-003: Database Migration Strategy

**Статус:** Принято  
**Дата:** 2025-01-27  
**Участники:** CTO, Database Architect, DevOps Engineer

## Контекст

Проект "Самокодер" использует Supabase (PostgreSQL) и требует надежной стратегии миграций для:
- Безопасного изменения схемы БД
- Версионирования изменений
- Rollback возможностей
- Production deployments

## Проблема

Текущее состояние:
- Статическая схема в `database/schema.sql`
- Отсутствие системы миграций
- Нет версионирования изменений БД
- Риск data loss при изменениях

## Решение

### 1. Alembic для миграций

```python
# alembic.ini
[alembic]
script_location = database/migrations
sqlalchemy.url = postgresql://user:pass@localhost/samokoder
```

### 2. Структура миграций

```
database/
├── migrations/
│   ├── versions/
│   │   ├── 001_initial_schema.py
│   │   ├── 002_add_user_preferences.py
│   │   └── 003_add_ai_usage_tracking.py
│   ├── env.py
│   └── script.py.mako
├── schema.sql (baseline)
└── seeds/
    ├── ai_providers.sql
    └── default_settings.sql
```

### 3. Migration Scripts

```python
# database/migrations/versions/001_initial_schema.py
"""Initial schema

Revision ID: 001
Revises: 
Create Date: 2025-01-27 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Create profiles table
    op.create_table('profiles',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('full_name', sa.String(), nullable=True),
        # ... other columns
        sa.PrimaryKeyConstraint('id')
    )
    
    # Enable RLS
    op.execute('ALTER TABLE profiles ENABLE ROW LEVEL SECURITY')
    
    # Create policies
    op.execute('''
        CREATE POLICY "Users see own profile" 
        ON profiles FOR ALL 
        USING (auth.uid() = id)
    ''')

def downgrade():
    op.drop_table('profiles')
```

### 4. Migration Management

```python
# database/migration_manager.py
import alembic
from alembic.config import Config
from alembic import command

class MigrationManager:
    def __init__(self, database_url: str):
        self.config = Config("alembic.ini")
        self.config.set_main_option("sqlalchemy.url", database_url)
    
    async def upgrade(self, revision: str = "head"):
        """Apply migrations up to revision"""
        command.upgrade(self.config, revision)
    
    async def downgrade(self, revision: str = "-1"):
        """Rollback to revision"""
        command.downgrade(self.config, revision)
    
    async def current_revision(self) -> str:
        """Get current revision"""
        return command.current(self.config)
    
    async def create_migration(self, message: str):
        """Create new migration"""
        command.revision(self.config, message=message, autogenerate=True)
```

### 5. Production Safety

#### Backup Strategy
```bash
# Pre-migration backup
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql

# Apply migration
alembic upgrade head

# Verify migration
alembic current
```

#### Rollback Plan
```bash
# Emergency rollback
alembic downgrade -1

# Restore from backup if needed
psql $DATABASE_URL < backup_20250127_100000.sql
```

### 6. CI/CD Integration

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
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install alembic psycopg2-binary
      
      - name: Run migrations
        run: |
          alembic upgrade head
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

## Реализация

### Фаза 1: Настройка Alembic (1 день)
- [ ] Установить Alembic
- [ ] Создать конфигурацию
- [ ] Настроить структуру директорий

### Фаза 2: Первая миграция (1 день)
- [ ] Создать baseline миграцию из schema.sql
- [ ] Протестировать upgrade/downgrade
- [ ] Создать backup процедуры

### Фаза 3: CI/CD интеграция (1 день)
- [ ] Добавить в GitHub Actions
- [ ] Настроить production deployment
- [ ] Создать rollback процедуры

### Фаза 4: Документация (1 день)
- [ ] Создать migration guidelines
- [ ] Обучить команду
- [ ] Создать troubleshooting guide

## Последствия

### Положительные
- Безопасные изменения схемы БД
- Версионирование всех изменений
- Rollback возможности
- Production safety

### Негативные
- Дополнительная сложность
- Требует обучения команды
- Overhead для простых изменений

## Альтернативы

1. **Manual SQL scripts** - отклонено из-за рисков
2. **Supabase Dashboard** - отклонено из-за отсутствия версионирования
3. **Flyway** - рассмотрено, но Alembic лучше интегрируется с Python

## Мониторинг

- Migration success/failure rates
- Rollback frequency
- Database performance impact
- Backup verification

## Rollback Plan

В случае проблем:
1. Немедленный rollback: `alembic downgrade -1`
2. Восстановление из backup
3. Анализ причин failure
4. Исправление и повторное применение