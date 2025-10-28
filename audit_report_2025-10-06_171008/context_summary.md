# Контекст и Гипотезы о Проекте Samokoder

**Дата аудита**: 2025-10-06
**Время начала**: 17:10:08

## Основные Гипотезы о Назначении Продукта

### ГИПОТЕЗА #1: SaaS платформа для AI-генерации приложений
**Источники**: 
- `README.md:3`: "SaaS платформа для генерации фулл-стек приложений из текстового описания с использованием AI агентов"
- `pyproject.toml:4`: "Samokoder Core Backend"

**Описание**: Samokoder - это платформа, которая позволяет пользователям генерировать полноценные web-приложения (фронтенд + бэкенд) из текстового описания, используя мульти-агентную AI систему.

### ГИПОТЕЗА #2: Мульти-агентная архитектура генерации кода
**Источники**:
- `README.md:335-351`: Описан поток AI агентов
- `docs/architecture.md:46-52`: Детальная схема orchestration
- Наличие 15+ агентов в `core/agents/`

**Описание**: Система использует специализированных AI-агентов для разных этапов разработки:
- SpecWriter - анализ требований
- Architect - проектирование архитектуры
- TechLead - декомпозиция задач
- Developer/CodeMonkey - генерация кода
- Executor - выполнение в Docker
- BugHunter/Troubleshooter - отладка

### ГИПОТЕЗА #3: BYOK (Bring Your Own Key) модель
**Источники**:
- `docs/architecture.md:321-324`: "User-provided API keys (encrypted в DB)"
- `.env.example:53-54`: Закомментированные переменные для API ключей

**Описание**: Пользователи могут использовать свои собственные API ключи для LLM провайдеров (OpenAI, Anthropic, Groq), что позволяет контролировать расходы и не зависеть от лимитов платформы.

## Технологический Стек

### Backend
**Источники**: `pyproject.toml:25-54`, `docs/architecture.md:16-21`
- **Язык**: Python 3.12+
- **Framework**: FastAPI (async)
- **БД**: PostgreSQL 15 + Redis 7
- **ORM**: SQLAlchemy (async)
- **Background Jobs**: ARQ (Redis-based)
- **Аутентификация**: JWT (python-jose)
- **Rate Limiting**: SlowAPI
- **Мониторинг**: Prometheus + Grafana

### Frontend
**Источники**: `frontend/package.json:14-78`
- **Framework**: React 18 + TypeScript
- **Build Tool**: Vite
- **UI Library**: Radix UI (20+ компонентов)
- **State Management**: TanStack Query (React Query)
- **Styling**: Tailwind CSS
- **Code Editor**: Monaco Editor
- **Terminal**: xterm.js

### Infrastructure
**Источники**: `docker-compose.yml`, `README.md:450-465`
- **Containerization**: Docker + Docker Compose
- **Reverse Proxy**: Traefik
- **Monitoring Stack**: Prometheus + Grafana + AlertManager
- **CI/CD**: GitHub Actions

## Бизнес-Логика и Процессы

### ГИПОТЕЗА #4: Процесс генерации проекта
**Источники**: `docs/architecture.md:229-250`

1. Пользователь создает проект через API
2. Задача попадает в очередь ARQ (Redis)
3. Worker подхватывает задачу
4. Orchestrator запускает pipeline агентов
5. Код генерируется параллельно (где возможно)
6. Результат тестируется в изолированном Docker контейнере
7. При ошибках запускается BugHunter
8. Готовый проект сохраняется в БД и файловой системе

### ГИПОТЕЗА #5: Монетизация через использование LLM
**Источники**:
- `docs/architecture.md:258-260`: "Cost: $0.01-$5 per project"
- Таблица `llm_requests` с полями `cost`, `tokens`

**Описание**: Основные расходы - это вызовы LLM API. Система отслеживает токены и стоимость каждого запроса для аналитики и биллинга.

## Процессы Разработки

### ГИПОТЕЗА #6: Production-Ready статус
**Источники**: 
- `README.md:467-513`: "PRODUCTION READY (95%)"
- Наличие comprehensive мониторинга
- CI/CD pipeline с 8 jobs

**Описание**: Проект находится в состоянии готовности к production использованию с завершенными критическими задачами по безопасности, производительности и надежности.

### ГИПОТЕЗА #7: Open Source с коммерческой лицензией
**Источники**:
- `README.md:400-404`: "FSL-1.1-MIT"
- `pyproject.toml:6`: "license = FSL-1.1-MIT"

**Описание**: Проект использует Functional Source License, что предполагает открытый код с ограничениями на коммерческое использование.

## Ключевые Операции

### Из package.json скриптов:
```bash
# Backend
uvicorn api.main:app --reload  # Запуск API
arq worker.main.WorkerSettings  # Запуск воркера
alembic upgrade head           # Миграции БД
pytest                         # Тесты

# Frontend  
npm run dev                    # Разработка
npm run build                  # Сборка
npm run lint                   # Линтинг
```

### Из CI/CD (.github/workflows/ci.yml):
- Lint Python (ruff)
- Lint Frontend (eslint)
- Backend Tests (pytest + coverage)
- Frontend Tests (jest)
- Security Scan (bandit, safety, trivy)
- Config Validation
- Docker Build

## Критические Компоненты

### ГИПОТЕЗА #8: Docker Socket как точка риска
**Источники**:
- `docker-compose.yml:39,92`: Mount `/var/run/docker.sock:ro`
- `docs/architecture.md:748-751`: "Docker Socket Access (HIGH)"

**Описание**: Система требует доступ к Docker socket для выполнения сгенерированного кода, что создает потенциальный риск безопасности (RCE).

### ГИПОТЕЗА #9: Large JSONB как bottleneck
**Источники**:
- `docs/architecture.md:492,828-830`: "ProjectState.data хранит весь state (100+ KB)"

**Описание**: Использование больших JSONB колонок для хранения состояния проекта может быть узким местом производительности при масштабировании.

## Целевая Аудитория

### ГИПОТЕЗА #10: Разработчики и технические предприниматели
**Источники**:
- Функциональность генерации full-stack приложений
- Поддержка различных технологических стеков
- BYOK модель для контроля расходов

**Описание**: Целевая аудитория - разработчики, которые хотят быстро прототипировать идеи, и технические предприниматели, создающие MVP.