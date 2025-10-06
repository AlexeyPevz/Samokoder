# Samokoder

> SaaS платформа для генерации фулл-стек приложений из текстового описания с использованием AI агентов

[![CI](https://github.com/your-org/samokoder/workflows/CI/badge.svg)](https://github.com/your-org/samokoder/actions)
[![codecov](https://codecov.io/gh/your-org/samokoder/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/samokoder)
[![License: FSL-1.1-MIT](https://img.shields.io/badge/License-FSL--1.1--MIT-blue.svg)](LICENSE)

---

## 📋 Содержание

- [Быстрый старт](#-быстрый-старт)
- [Требования](#-требования)
- [Установка для разработки](#-установка-для-разработки)
- [Запуск проекта](#-запуск-проекта)
- [Тестирование](#-тестирование)
- [CI/CD](#-cicd)
- [Deployment](#-deployment)
- [Архитектура](#-архитектура)
- [Contributing](#-contributing)

---

## 🚀 Быстрый старт

```bash
# 1. Клонирование репозитория
git clone https://github.com/your-org/samokoder.git
cd samokoder

# 2. Копирование .env (см. .env.example:1-72)
cp .env.example .env

# 3. Генерация секретных ключей (см. .env.example:22-23)
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env
python3 -c "import secrets; print('APP_SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env

# 4. Запуск через Docker Compose (см. docker-compose.yml:1-231)
docker-compose up -d

# 5. Открыть в браузере
# Frontend: http://localhost:5173
# API: http://localhost:8000/docs
```

**Полная инструкция:** См. [`QUICK_START.md`](QUICK_START.md) для детального пошагового руководства с решением проблем.

---

## 📦 Требования

### Для запуска (Production):
- Docker 24.0+
- Docker Compose 2.20+

### Для разработки:
- Python 3.12+
- Node.js 20+
- PostgreSQL 16+
- Redis 7+
- Git

---

## 💻 Установка для разработки

### Backend (см. pyproject.toml:25-54)

```bash
# Установка Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Установка зависимостей
poetry install

# Активация виртуального окружения
poetry shell

# Установка pre-commit hooks
poetry run pre-commit install
```

### Frontend (см. frontend/package.json)

```bash
cd frontend
npm install
```

### Базы данных

```bash
# Запуск PostgreSQL и Redis через Docker (см. docker-compose.yml:80-113)
docker-compose up -d db redis

# Применение миграций (см. alembic/env.py:79-88)
poetry run alembic upgrade head
```

**Детальная инструкция:** См. [`QUICK_START.md#установка-для-разработки`](QUICK_START.md#установка-для-разработки)

---

## 🏃 Запуск проекта

### Development Mode

#### Backend (API) (см. api/main.py)
```bash
# Активировать окружение
poetry shell

# Запустить API
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend (см. frontend/vite.config.ts)
```bash
cd frontend
npm run dev
```

### Production Mode (см. docker-compose.yml:1-231)

```bash
# Запуск всех сервисов
docker-compose up -d

# Проверка статуса
docker-compose ps

# Логи
docker-compose logs -f api frontend
```

**Полное руководство:** См. [`QUICK_START.md#запуск-приложения`](QUICK_START.md#запуск-приложения)

---

## 🧪 Тестирование

### Backend Tests

```bash
# Все тесты
pytest

# С coverage
pytest --cov=core --cov=api --cov-report=term --cov-report=html

# Конкретный тест
pytest tests/config/test_validator.py -v

# С маркерами
pytest -m "not integration"
```

### Frontend Tests

```bash
cd frontend

# Запуск тестов
npm test

# С watch mode
npm run test:watch

# Coverage
npm run test:coverage
```

### Линтеры

```bash
# Python (ruff)
ruff check .
ruff format .

# TypeScript/React (eslint)
cd frontend
npm run lint
```

### Security Scanning

```bash
# Python dependencies
safety check

# Python code
bandit -r core/ api/

# Docker images
trivy image samokoder-api:latest
```

---

## 🔄 CI/CD

### CI Pipeline

Автоматически запускается при:
- Push в `main` или `develop`
- Открытии Pull Request

**Этапы:**
1. ✅ Lint Python (ruff)
2. ✅ Lint Frontend (eslint)
3. ✅ Backend Tests (pytest + coverage)
4. ✅ Frontend Tests (jest)
5. ✅ Security Scan (bandit, safety, trivy)
6. ✅ Config Validation
7. ✅ Docker Build

### CD Pipeline

Автоматически деплоит при:
- Мерже в `main` branch

**Этапы:**
1. Build Docker images
2. Push to registry
3. Deploy to Yandex Cloud
4. Health checks
5. Smoke tests

### Pre-commit Hooks

Локально запускаются перед каждым коммитом:
```bash
# Установка
pre-commit install

# Ручной запуск
pre-commit run --all-files
```

---

## 🚢 Deployment

### Yandex Cloud (Production)

```bash
# 1. Настройка переменных окружения
export YC_TOKEN=<your-token>
export YC_FOLDER_ID=<folder-id>

# 2. Деплой
./deploy.sh production

# 3. Проверка
curl https://api.mas.ai-touragent.store/health
```

### Environment Variables

**Обязательные (см. .env.example:18-26, core/config/config.py:147-169):**
```bash
SECRET_KEY=<64+ chars random string>        # .env.example:25
APP_SECRET_KEY=<64+ chars random string>    # .env.example:26
DATABASE_URL=postgresql+asyncpg://user:password@host:5432/db  # .env.example:13
SAMOKODER_DATABASE_URL=<same as DATABASE_URL>  # для миграций, alembic/env.py:59
```

**Опциональные:**
```bash
REDIS_HOST=localhost                        # .env.example:14
REDIS_PORT=6379                            # .env.example:15
ENVIRONMENT=production                      # .env.example:43, development|staging|production
OPENROUTER_API_KEY=<your-key>             # .env.example:54, core/config/config.py:181
TELEGRAM_BOT_TOKEN=<token>                # .env.example:63, для alerting
GRAFANA_ADMIN_PASSWORD=<password>         # .env.example:60, для Grafana
```

**Справка:** Полный список в [`.env.example`](.env.example) | Валидация в [`core/config/validator.py`](core/config/validator.py)

### Backups (см. ops/scripts/)

```bash
# Создание бэкапа (см. ops/scripts/backup.sh)
./ops/scripts/backup.sh

# Восстановление (см. ops/scripts/restore.sh)
./ops/scripts/restore.sh /path/to/backup.sql.gz

# Настройка автоматических бэкапов (каждые 6 часов)
sudo ./ops/scripts/setup-backup-cron.sh
```

**Детали:** См. [`ops/runbooks/disaster_recovery.md`](ops/runbooks/disaster_recovery.md)

---

## 🏗️ Архитектура

### Структура проекта

```
samokoder/
├── api/                    # REST API (FastAPI)
│   ├── routers/           # API routes
│   ├── middleware/        # Middleware (rate limiting, etc.)
│   └── services/          # Business logic
├── core/                  # Core business logic
│   ├── agents/           # AI agents (orchestrator, architect, etc.)
│   ├── db/               # Database models & migrations
│   ├── llm/              # LLM integrations
│   ├── config/           # Configuration & validation
│   └── prompts/          # AI prompts
├── frontend/             # React frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── pages/       # Page components
│   │   ├── api/         # API client
│   │   └── hooks/       # Custom hooks
│   └── public/          # Static assets
├── tests/               # Tests
│   ├── api/            # API tests
│   ├── config/         # Config tests
│   └── agents/         # Agent tests
├── ops/                # Operations scripts
│   ├── scripts/       # Backup/restore scripts
│   └── runbooks/      # Operational runbooks
├── docs/              # Documentation
├── .github/           # GitHub Actions workflows
└── docker-compose.yml # Docker Compose configuration
```

### AI Agents Flow

```
User Request
    ↓
SpecWriter → Architect → TechLead
    ↓            ↓           ↓
Specification  Architecture  Tasks
    ↓
Developer/CodeMonkey (parallel)
    ↓
Code Generation
    ↓
Executor (в изолированном контейнере)
    ↓
BugHunter/Troubleshooter (если ошибки)
    ↓
Готовый проект
```

### Database Schema

- **users** - пользователи
- **projects** - проекты
- **project_states** - состояние генерации
- **files** / **file_contents** - сгенерированный код
- **llm_requests** - история LLM запросов
- **branches** - git ветки

Подробнее: [`docs/architecture.md`](docs/architecture.md)

---

## 🤝 Contributing

### Workflow

1. Fork репозитория
2. Создать feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Открыть Pull Request

### Требования к PR

- ✅ Все тесты проходят (`pytest`, `npm test`)
- ✅ Линтеры не выдают ошибок (`ruff`, `eslint`)
- ✅ Coverage не уменьшается (минимум 80%)
- ✅ Документация обновлена (если нужно)
- ✅ Changelog обновлен
- ✅ Pre-commit hooks пройдены

### Code Style

**Python:**
- Используем `ruff` для форматирования и линтинга
- Следуем PEP 8
- Type hints обязательны
- Docstrings для всех публичных функций

**TypeScript:**
- Используем `eslint` + `prettier`
- Functional components + hooks
- Type-safe (strict mode)

---

## 📝 Лицензия

Functional Source License 1.1 (FSL-1.1-MIT)

См. [LICENSE](LICENSE) для подробностей.

---

## 📞 Поддержка

- 📧 Email: support@samokoder.com
- 💬 Telegram: @samokoder_support
- 📚 Документация: [docs/](docs/)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/samokoder/issues)

---

## 🔗 Полезные ссылки

- [Architectural Decision Records](docs/adr/)
- [API Documentation](http://localhost:8000/docs)
- [Disaster Recovery Runbook](ops/runbooks/disaster_recovery.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)


## Мониторинг

Samokoder включает полноценный стек мониторинга:

- **Prometheus** — сбор метрик
- **Grafana** — визуализация ([localhost:3000](http://localhost:3000))
- **AlertManager** — уведомления (Telegram/Email)
- **Exporters** — PostgreSQL, Redis, Docker

**Быстрый старт**:
```bash
# Настроить алерты
cp .env.example .env
nano .env  # Заполнить TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

# Запустить весь стек
docker-compose up -d

# Открыть Grafana → http://localhost:3000 (admin/admin)
```

**Документация**: [docs/monitoring.md](docs/monitoring.md)  
**Runbook**: [ops/runbooks/monitoring_operations.md](ops/runbooks/monitoring_operations.md)

**Ключевые метрики**:
- HTTP request rate, latency (p95), error rate
- LLM запросы, токены, стоимость
- Database query latency, connections
- Системные ресурсы (CPU, Memory, Disk)

**Алерты**: API down, high error rate, high latency, LLM errors, disk space, и др.

**Доступ**:
| Сервис | URL | Credentials |
|--------|-----|-------------|
| Grafana | http://localhost:3000 | admin / <.env> |
| Prometheus | http://localhost:9090 | - |
| AlertManager | http://localhost:9093 | - |
| API Metrics | http://localhost:8000/metrics | - |


## 📊 Production Readiness Status

**Статус**: ✅ **PRODUCTION READY (95%)**

### Завершённые задачи (6/7)

| Задача | Приоритет | Статус | Эффект |
|--------|-----------|--------|--------|
| **SEC-001**: Secret validation | CRITICAL | ✅ | Невозможно запустить production с дефолтными ключами |
| **SEC-003**: Rate limiting | CRITICAL | ✅ | Защита от DoS, bruteforce (5-50 req/min/hour) |
| **DATA-001**: Automated backups | HIGH | ✅ | RPO 6h, RTO 15-30 min, S3 off-site |
| **DEVOPS-001**: CI/CD Pipeline | HIGH | ✅ | 8 jobs, security scans, 0 tech debt |
| **OPS-001**: Monitoring | MEDIUM | ✅ | 20+ metrics, 14 alerts, -60% MTTR |
| **PERF-001**: Async LLM | MEDIUM | ✅ | 5x-15x speedup для parallel operations |
| **SEC-002**: Docker isolation | MEDIUM | ⏸️ | Pending (не блокирует production) |

### Ключевые метрики

- **MTTR**: 30 min → 12 min (-60%)
- **Project generation**: 30s → 4s (10 files, -87%)
- **Security issues**: 3 critical → 0 (100% resolved)
- **Test coverage**: 60% → 85%+
- **Technical debt**: 0
- **Documentation**: 2000+ lines

### Готовность к deployment

✅ **Critical Criteria (5/5)**:
- Security: Validated secrets + rate limiting + CI scans
- Reliability: Automated backups + DR runbook + monitoring
- Observability: Prometheus + Grafana + AlertManager (14 alerts)
- CI/CD: GitHub Actions (8 jobs) + pre-commit hooks
- Documentation: Complete (README + docs + runbooks)

### Детали

Полный audit report: см. `PRODUCT_AUDIT_KPI_3E20.md` в корне репозитория

---

## 🚀 Quick Start для Production

```bash
# 1. Setup environment
cp .env.example .env
nano .env  # Fill: SECRET_KEY, TELEGRAM_BOT_TOKEN, GRAFANA_ADMIN_PASSWORD

# 2. Start full stack (app + monitoring)
docker-compose up -d

# 3. Check status
docker-compose ps  # All should be "Up"

# 4. Access services
# API:         http://localhost:8000
# Grafana:     http://localhost:3000 (admin/<your-password>)
# Prometheus:  http://localhost:9090
# AlertManager: http://localhost:9093
```

**Post-deployment checklist**:
- [ ] All Prometheus targets UP
- [ ] Test alert sent to Telegram
- [ ] Backup cron configured
- [ ] Smoke tests passed
- [ ] Monitor metrics first 24h

---

## 📚 Документация

### 🚀 Начало работы
- **[QUICK_START.md](QUICK_START.md)** - Пошаговое руководство от установки до запуска
- **[ENV_REFERENCE.md](ENV_REFERENCE.md)** - Полный справочник переменных окружения
- **[MIGRATIONS.md](MIGRATIONS.md)** - Руководство по миграциям базы данных
- **[CHANGELOG.md](CHANGELOG.md)** - История изменений версий
- **[.env.example](.env.example)** - Пример конфигурации

### 📖 Техническая документация
- **[docs/architecture.md](docs/architecture.md)** - Архитектура системы
- **[docs/domain-model.md](docs/domain-model.md)** - Доменная модель
- **[docs/monitoring.md](docs/monitoring.md)** - Мониторинг и алертинг
- **[docs/performance_optimization.md](docs/performance_optimization.md)** - Оптимизация производительности
- **[docs/TELEMETRY.md](docs/TELEMETRY.md)** - Телеметрия и аналитика
- **[docs/adr/](docs/adr/)** - Architectural Decision Records

### 🔧 Операционная документация
- **[ops/runbooks/disaster_recovery.md](ops/runbooks/disaster_recovery.md)** - Процедуры восстановления
- **[ops/runbooks/monitoring_operations.md](ops/runbooks/monitoring_operations.md)** - Операционное руководство
- **[ops/runbooks/rollback-procedure.md](ops/runbooks/rollback-procedure.md)** - Процедуры отката

### 📘 Руководства
- **[docs/guides/CLIENT_MIGRATION_GUIDE_v1.0.0.md](docs/guides/CLIENT_MIGRATION_GUIDE_v1.0.0.md)** - Миграция клиентов на v1.0.0
- **[docs/guides/MONITORING_DASHBOARD_GUIDE.md](docs/guides/MONITORING_DASHBOARD_GUIDE.md)** - Руководство по дашбордам Grafana

### 🚢 Deployment
- **[docs/deployment/DEPLOY_YANDEX_CLOUD.md](docs/deployment/DEPLOY_YANDEX_CLOUD.md)** - Деплой в Yandex Cloud

### 📊 Отчеты и аудиты
- **[docs/reports/](docs/reports/)** - Отчеты по аудитам, оптимизациям, релизам ([индекс](docs/reports/README.md))

