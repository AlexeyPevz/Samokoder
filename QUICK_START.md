# 🚀 Quick Start Guide

> Пошаговое руководство по развертыванию Samokoder от установки до запуска

## 📋 Содержание

- [Системные требования](#системные-требования)
- [Быстрый старт (Docker)](#быстрый-старт-docker)
- [Установка для разработки](#установка-для-разработки)
- [Настройка окружения](#настройка-окружения)
- [Миграции базы данных](#миграции-базы-данных)
- [Запуск приложения](#запуск-приложения)
- [Проверка работоспособности](#проверка-работоспособности)
- [Решение проблем](#решение-проблем)

---

## Системные требования

### Production (Docker)
- **Docker** 24.0+ ([установка](https://docs.docker.com/get-docker/))
- **Docker Compose** 2.20+ (включен в Docker Desktop)
- **Минимум 4GB RAM**, 10GB свободного места на диске

### Development
- **Python** 3.9+ (рекомендуется 3.12+)
- **Poetry** 1.7+ ([установка](https://python-poetry.org/docs/#installation))
- **Node.js** 20+ ([установка](https://nodejs.org/))
- **PostgreSQL** 15+ (опционально, можно использовать Docker)
- **Redis** 7+ (опционально, можно использовать Docker)
- **Git** 2.30+

---

## Быстрый старт (Docker)

### Шаг 1: Клонирование репозитория

```bash
git clone https://github.com/your-org/samokoder.git
cd samokoder
```

### Шаг 2: Настройка переменных окружения

```bash
# Копируем пример конфигурации
cp .env.example .env

# Генерируем секретные ключи (ОБЯЗАТЕЛЬНО!)
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env
python3 -c "import secrets; print('APP_SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env
```

**Важно:** Проверьте файл `.env` и настройте дополнительные параметры:

```bash
nano .env  # или любой текстовый редактор
```

Обязательные параметры для production:
- `SECRET_KEY` - сгенерирован выше
- `APP_SECRET_KEY` - сгенерирован выше  
- `GRAFANA_ADMIN_PASSWORD` - пароль для Grafana (по умолчанию: admin)
- `TELEGRAM_BOT_TOKEN` - токен бота для алертов (опционально)
- `TELEGRAM_CHAT_ID` - ID чата для алертов (опционально)

**Справка:** См. [`.env.example`](.env.example#L1-L72) для полного списка параметров.

### Шаг 3: Запуск всех сервисов

```bash
docker-compose up -d
```

**Что происходит:**
- Запускаются контейнеры: `frontend`, `api`, `worker`, `db` (PostgreSQL), `redis`
- Запускаются сервисы мониторинга: `prometheus`, `grafana`, `alertmanager`
- Применяются миграции базы данных
- Инициализируются volumes для данных

**Справка:** См. [`docker-compose.yml`](docker-compose.yml#L1-L231) для конфигурации сервисов.

### Шаг 4: Проверка статуса

```bash
# Проверить статус всех контейнеров (должны быть в состоянии "Up")
docker-compose ps

# Посмотреть логи
docker-compose logs -f api frontend
```

### Шаг 5: Доступ к сервисам

| Сервис | URL | Credentials |
|--------|-----|-------------|
| **Frontend** | http://localhost:5173 | - |
| **API** | http://localhost:8000 | - |
| **API Docs** | http://localhost:8000/docs | - |
| **Grafana** | http://localhost:3000 | admin / (из .env) |
| **Prometheus** | http://localhost:9090 | - |
| **AlertManager** | http://localhost:9093 | - |

---

## Установка для разработки

### Шаг 1: Клонирование и подготовка

```bash
git clone https://github.com/your-org/samokoder.git
cd samokoder
```

### Шаг 2: Backend (Python)

```bash
# Установка Poetry (если не установлен)
curl -sSL https://install.python-poetry.org | python3 -

# Установка зависимостей
poetry install

# Активация виртуального окружения
poetry shell
```

**Справка:** 
- Зависимости определены в [`pyproject.toml`](pyproject.toml#L25-L54)
- Используется Poetry для управления зависимостями (см. [`pyproject.toml`](pyproject.toml#L1-L23))

### Шаг 3: Frontend (Node.js)

```bash
cd frontend

# Установка зависимостей
npm install

# Возврат в корень проекта
cd ..
```

**Справка:** Конфигурация в [`frontend/package.json`](frontend/package.json)

### Шаг 4: Базы данных

**Вариант A: Использовать Docker (рекомендуется)**

```bash
# Запустить только PostgreSQL и Redis
docker-compose up -d db redis

# Проверить статус
docker-compose ps db redis
```

**Вариант B: Локальная установка**

```bash
# PostgreSQL
sudo apt-get install postgresql-15  # Ubuntu/Debian
brew install postgresql@15          # macOS

# Redis
sudo apt-get install redis-server   # Ubuntu/Debian
brew install redis                  # macOS

# Запуск сервисов
sudo systemctl start postgresql redis  # Linux
brew services start postgresql redis   # macOS
```

### Шаг 5: Настройка окружения

```bash
# Копировать .env
cp .env.example .env

# Редактировать .env
nano .env
```

**Для разработки настройте:**

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/samokoder
SAMOKODER_DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/samokoder

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Security (генерируйте новые ключи!)
SECRET_KEY=<generated>
APP_SECRET_KEY=<generated>

# Environment
ENVIRONMENT=development

# Frontend
FRONTEND_URL=http://localhost:5173
```

**Справка:** Все параметры описаны в [`.env.example`](.env.example#L1-L72)

### Шаг 6: Pre-commit hooks

```bash
# Установка pre-commit
poetry run pre-commit install

# Тестовый прогон
poetry run pre-commit run --all-files
```

---

## Настройка окружения

### Обязательные переменные

| Переменная | Описание | Источник |
|------------|----------|----------|
| `SECRET_KEY` | Ключ для JWT токенов (64+ символов) | См. [`.env.example:25`](.env.example#L25) |
| `APP_SECRET_KEY` | Ключ для шифрования (64+ символов) | См. [`.env.example:26`](.env.example#L26) |
| `DATABASE_URL` | URL PostgreSQL базы данных | См. [`.env.example:13`](.env.example#L13) |
| `SAMOKODER_DATABASE_URL` | Дублирует DATABASE_URL для миграций | См. [`alembic/env.py:59`](alembic/env.py#L59) |

**Генерация секретных ключей:**

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

**Справка:** Валидация ключей в [`core/config/validator.py`](core/config/validator.py)

### Опциональные переменные

#### LLM Providers

```bash
OPENROUTER_API_KEY=your_key_here
OPENROUTER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions
```

**Справка:** Конфигурация в [`core/config/config.py:87-110`](core/config/config.py#L87-L110)

#### Monitoring

```bash
GRAFANA_ADMIN_PASSWORD=secure_password
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

**Справка:** 
- Grafana конфигурация: [`docker-compose.yml:137-155`](docker-compose.yml#L137-L155)
- AlertManager конфигурация: [`docker-compose.yml:157-177`](docker-compose.yml#L157-L177)

---

## Миграции базы данных

### Применение миграций

```bash
# Production (Docker)
docker-compose exec api alembic upgrade head

# Development
poetry run alembic upgrade head
```

**Справка:**
- Миграции в директории [`alembic/versions/`](alembic/versions/)
- Конфигурация Alembic: [`alembic.ini`](alembic.ini#L1-L147)
- Логика миграций: [`alembic/env.py`](alembic/env.py#L1-L94)

### Создание новой миграции

```bash
# Автогенерация на основе моделей
poetry run alembic revision --autogenerate -m "description"

# Просмотр истории миграций
poetry run alembic history

# Откат на одну миграцию назад
poetry run alembic downgrade -1
```

**Справка:** Модели базы данных в [`core/db/models/`](core/db/models/)

### Переменные окружения для миграций

Alembic использует переменную `SAMOKODER_DATABASE_URL` с приоритетом над `alembic.ini`:

```python
# alembic/env.py:59
url = os.environ.get("SAMOKODER_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
```

---

## Запуск приложения

### Production (Docker)

```bash
# Запуск всех сервисов
docker-compose up -d

# Просмотр логов
docker-compose logs -f

# Остановка
docker-compose down

# Полная очистка (включая volumes)
docker-compose down -v
```

### Development

**Терминал 1: Backend API**

```bash
poetry shell
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

**Справка:** Конфигурация API в [`api/main.py`](api/main.py)

**Терминал 2: Background Worker**

```bash
poetry shell
arq worker.main.WorkerSettings
```

**Справка:** Конфигурация worker в [`worker/main.py`](worker/main.py)

**Терминал 3: Frontend**

```bash
cd frontend
npm run dev
```

**Справка:** Конфигурация Vite в [`frontend/vite.config.ts`](frontend/vite.config.ts)

**Терминал 4: Базы данных (если используете Docker)**

```bash
docker-compose up db redis
```

---

## Проверка работоспособности

### 1. Health Checks

```bash
# API health
curl http://localhost:8000/health
# Ожидаемый ответ: {"status":"healthy"}

# Frontend
curl http://localhost:5173
# Ожидаемый ответ: HTML страница

# Prometheus metrics
curl http://localhost:8000/metrics
# Ожидаемый ответ: метрики в формате Prometheus
```

### 2. Database Connection

```bash
# Development
poetry run python -c "
from core.config.config import get_config
from sqlalchemy.ext.asyncio import create_async_engine
import asyncio

async def test_db():
    config = get_config()
    engine = create_async_engine(config.database_url)
    async with engine.connect() as conn:
        print('✓ Database connection successful')
    await engine.dispose()

asyncio.run(test_db())
"
```

### 3. Redis Connection

```bash
# Test Redis
redis-cli ping
# Ожидаемый ответ: PONG

# Or via Python
poetry run python -c "
import redis
r = redis.Redis(host='localhost', port=6379)
print('✓ Redis connection:', r.ping())
"
```

### 4. API Documentation

Откройте http://localhost:8000/docs для интерактивной документации Swagger UI.

### 5. Monitoring

Откройте http://localhost:3000 (Grafana) и проверьте:
- ✅ Dashboards загружаются
- ✅ Prometheus подключен (Configuration → Data Sources)
- ✅ Метрики отображаются

---

## Решение проблем

### Проблема: "SECRET_KEY validation failed"

**Причина:** Используются дефолтные секретные ключи из `.env.example`

**Решение:**
```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env
python3 -c "import secrets; print('APP_SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env
```

**Справка:** Валидация в [`core/config/validator.py`](core/config/validator.py)

### Проблема: "Database connection failed"

**Причина:** PostgreSQL не запущен или неверный DATABASE_URL

**Решение:**
```bash
# Проверить статус PostgreSQL
docker-compose ps db  # Docker
sudo systemctl status postgresql  # Linux
brew services list  # macOS

# Проверить URL в .env
grep DATABASE_URL .env

# Проверить подключение
psql -h localhost -p 5432 -U user -d samokoder
```

### Проблема: "Alembic migration failed"

**Причина:** База данных не инициализирована или несовместимая схема

**Решение:**
```bash
# Проверить текущую версию
poetry run alembic current

# Откатить миграции
poetry run alembic downgrade base

# Применить заново
poetry run alembic upgrade head
```

**Справка:** См. [`alembic/env.py`](alembic/env.py) для логики миграций

### Проблема: "Port already in use"

**Причина:** Порт занят другим процессом

**Решение:**
```bash
# Найти процесс на порту 8000
lsof -i :8000  # macOS/Linux
netstat -ano | findstr :8000  # Windows

# Убить процесс
kill -9 <PID>

# Или изменить порт в команде запуска
uvicorn api.main:app --port 8001
```

### Проблема: "Frontend build failed"

**Причина:** Устаревшие зависимости или несовместимая версия Node.js

**Решение:**
```bash
# Проверить версию Node.js
node --version  # должна быть 20+

# Очистить кэш и переустановить
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### Проблема: "Docker Compose: network not found"

**Причина:** Внешняя сеть `web` не существует

**Решение:**
```bash
# Создать сеть
docker network create web

# Или удалить из docker-compose.yml секцию:
# networks:
#   web:
#     external: true
```

**Справка:** См. [`docker-compose.yml:219-223`](docker-compose.yml#L219-L223)

---

## Дополнительные ресурсы

- **Архитектура:** [`docs/architecture.md`](docs/architecture.md)
- **Мониторинг:** [`docs/monitoring.md`](docs/monitoring.md)
- **Производительность:** [`docs/performance_optimization.md`](docs/performance_optimization.md)
- **Операционные runbooks:** [`ops/runbooks/`](ops/runbooks/)
- **Миграция клиентов:** [`docs/guides/CLIENT_MIGRATION_GUIDE_v1.0.0.md`](docs/guides/CLIENT_MIGRATION_GUIDE_v1.0.0.md)
- **Deployment в Yandex Cloud:** [`docs/deployment/DEPLOY_YANDEX_CLOUD.md`](docs/deployment/DEPLOY_YANDEX_CLOUD.md)
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md)

---

## Поддержка

- 📧 Email: support@samokoder.com
- 💬 Telegram: @samokoder_support
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/samokoder/issues)
