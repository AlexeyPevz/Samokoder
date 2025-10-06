# Контекст и гипотезы (Фаза 1)

Статус: ГИПОТЕЗА. Ниже — реконструкция назначения продукта, бизнес-логики, стека и процессов на основе артефактов репозитория.

## Назначение продукта
- Платформа Samokoder — SaaS для генерации full‑stack приложений из текстового описания с помощью мульти‑агентной AI‑системы.
- Пользователь создаёт проект, платформа через конвейер агентов (SpecWriter → Architect → TechLead → Developer/CodeMonkey → Executor → BugHunter) генерирует код, выполняет его в контейнере и сохраняет результаты.
- Ценностное предложение: ускорение проектирования и реализации приложений, BYOK-модель (пользователь приносит свои LLM‑ключи), аналитика использования токенов, мониторинг, DevOps‑обвязка.
- Источники: README.md; docs/architecture.md; docs/domain-model.md; openapi.yaml; core/agents/*; worker/main.py.

## Целевая аудитория и сценарии
- Индивидуальные разработчики и малые команды, ускоряющие прототипирование.
- SaaS‑компании/студии, желающие полуавтоматизировать поставку типовых приложений.
- Сценарии: создание/редактирование проекта, генерация кода, превью, интеграции (GitHub/GitVerse), учёт токенов и затрат.
- Источники: README.md; openapi.yaml (tags: projects, keys, plugins, analytics, usage, user).

## Технологический стек
- Backend: Python 3.12+, FastAPI (async), SQLAlchemy 2.x (asyncpg), Alembic, Redis (ARQ), httpx, tenacity, Prometheus.
- Frontend: React 18, TypeScript, Vite, Radix UI, React Query, Tailwind.
- Инфраструктура: Docker/Docker Compose, Traefik, Prometheus, Grafana, AlertManager; деплой — Yandex Cloud.
- Источники: pyproject.toml; frontend/package.json; docker-compose.yml; Dockerfile; docs/monitoring.md.

## Архитектура и потоки данных
- Monorepo: `api/` (FastAPI) + `core/` (домейн и агенты) + `worker/` (ARQ) + `frontend/`.
- Поток: запрос на генерацию → запись в БД → постановка задачи в Redis → worker запускает конвейер агентов → файлы и состояние сохраняются в БД/FS → фронтенд получает обновления (WS/поллинг).
- Источники: docs/architecture.md; api/main.py; worker/main.py; core/state/*; core/agents/*.

## Доменная модель (высокоуровнево)
- User (bcrypt, JWT), Project, Branch, ProjectState (JSONB snapshot), File/FileContent, LLMRequest, ExecLog, токены провайдеров (зашифрованы Fernet), RevokedToken.
- Источники: core/db/models/*; docs/domain-model.md; alembic/versions/*.

## Безопасность и комплаенс
- JWT с jti и отзывом токенов, httpOnly cookies; rate limiting (SlowAPI+Redis); валидация секретов на старте.
- Ограничение размера запросов; строгий CORS (prod); Docker‑hardening (частично, docker.sock read‑only, cap_drop ALL, no‑new‑privileges).
- Риски: доступ к docker.sock (даже read‑only — повышенный риск), LLM prompt injection, path traversal (требует строгой валидации), неполная изоляция превью‑процессов.
- Источники: api/main.py; api/middleware/*; core/config/validator.py; docker-compose.yml; docs/adr/004-security-hardening-docker-isolation.md; openapi.yaml (x-discrepancies).

## CI/CD и качество
- GitHub Actions: линтинг (ruff/eslint), тесты (pytest/jest), security scans (bandit, safety, trivy), docker build, config validation, aggregate job.
- Покрытие 80%+ заявлено; pre-commit hooks.
- Источники: .github/workflows/ci.yml; README.md; CHANGELOG.md.

## Эксплуатация и наблюдаемость
- Prometheus эндпоинт `/metrics`, кастомные метрики HTTP/LLM/DB/бизнес; dashboards и алерты; бэкапы PostgreSQL.
- Источники: api/middleware/metrics.py; docs/monitoring.md; docker-compose.yml (monitoring stack).

## Первичные несоответствия/риски (наблюдения)
- docker.sock монтирован (пусть и ro) — риск RCE/побега из контейнера. Источник: docker-compose.yml:39,92.
- Смешение sync/async ранее фиксировалось, но возможны остаточные места; проверить системно. Источники: openapi.yaml x-discrepancies; фиксы в routers/*.
- Превью запускает команды разработки; нужна строгая изоляция/квоты/таймауты. Источники: api/routers/preview.py; core/proc/process_manager.py.
- Потенциальные N+1 и крупные JSONB в ProjectState. Источники: docs/architecture.md (Performance Bottlenecks), core/db/models/*.

