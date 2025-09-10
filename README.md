# 🚀 Самокодер v1.0.0 - AI-генератор кода

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/samokoder/samokoder)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/react-18.3.1-blue.svg)](https://reactjs.org)
[![FastAPI](https://img.shields.io/badge/fastapi-0.104.1-green.svg)](https://fastapi.tiangolo.com)
[![TypeScript](https://img.shields.io/badge/typescript-5.6.2-blue.svg)](https://www.typescriptlang.org)

> **Полнофункциональная платформа для генерации кода с помощью ИИ**  
> Включает современный React фронтенд, FastAPI бэкенд, PostgreSQL базу данных и интеграцию с множественными AI провайдерами.

## ✨ Основные возможности

### 🔐 **Аутентификация и безопасность**
- JWT токены с многофакторной аутентификацией (MFA)
- Role-Based Access Control (RBAC) система
- Rate limiting защита от DDoS атак
- ASVS Level 2 соответствие безопасности
- Шифрование данных в покое и в движении

### 📁 **Управление проектами**
- Создание проектов с AI конфигурацией
- CRUD операции для проектов
- Поиск и фильтрация проектов
- Статусы проектов в реальном времени
- Прогресс генерации с live updates
- Экспорт проектов в различных форматах

### 🤖 **AI интеграция**
- Множественные AI провайдеры (OpenAI, Anthropic, Groq, OpenRouter)
- Fallback механизм при недоступности провайдеров
- Streaming responses для чата
- Usage tracking и биллинг
- Модель-агент система с GPT-Pilot
- Контекстное общение с AI

### 🎨 **Пользовательский интерфейс**
- React 18 с TypeScript
- Responsive дизайн (mobile-first)
- WCAG 2.2 AA соответствие доступности
- Core Web Vitals оптимизация
- Lazy loading и code splitting
- Skeleton loading для улучшения UX
- Темная/светлая тема

### 🏗️ **Backend и инфраструктура**
- FastAPI с async/await
- PostgreSQL через Supabase с RLS
- Redis для кэширования и сессий
- Alembic миграции БД
- Connection pooling для производительности
- Structured logging с Prometheus
- Health checks для всех сервисов

### 🚀 **DevOps и мониторинг**
- Docker multi-stage builds
- GitHub Actions CI/CD pipeline
- Blue-Green deployment стратегия
- Golden Signals мониторинг
- Automated testing (Unit, Integration, E2E)
- Security scanning в CI/CD

## 🚀 Быстрый старт

### 📋 Предварительные требования

- **Python 3.9+**
- **Node.js 18+**
- **Docker** (опционально)
- **Git**

### ⚡ Установка за 5 минут

#### 1. Клонирование репозитория
```bash
git clone https://github.com/samokoder/samokoder.git
cd samokoder
```

#### 2. Настройка переменных окружения
```bash
# Скопируйте пример конфигурации
cp .env.example .env

# Отредактируйте .env файл
nano .env
```

#### 3. Установка зависимостей
```bash
# Backend
pip install -r requirements.txt

# Frontend
cd frontend
npm install
cd ..
```

#### 4. Настройка базы данных
```bash
# Выполните миграции
python -m alembic upgrade head

# Или используйте Supabase (рекомендуется)
python scripts/setup_supabase.py
```

#### 5. Запуск приложения
```bash
# Автоматический запуск (рекомендуется)
./scripts/start_dev.sh

# Или ручной запуск
# Терминал 1 - Backend
python run_server.py

# Терминал 2 - Frontend
cd frontend && npm run dev
```

#### 6. Доступ к приложению
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🔧 Конфигурация

### 📁 Структура проекта

```
samokoder/
├── 📁 frontend/                 # React фронтенд
│   ├── 📁 src/
│   │   ├── 📁 components/      # UI компоненты
│   │   │   ├── 📁 accessibility/  # Доступность
│   │   │   ├── 📁 dashboard/      # Дашборд
│   │   │   └── 📁 ui/             # Базовые UI
│   │   ├── 📁 pages/          # Страницы приложения
│   │   ├── 📁 api/            # API клиенты
│   │   ├── 📁 contexts/       # React контексты
│   │   ├── 📁 hooks/          # Custom hooks
│   │   ├── 📁 lib/            # Утилиты
│   │   └── 📁 styles/         # Стили
│   ├── 📄 package.json
│   └── 📄 vite.config.ts
├── 📁 backend/                 # Python бэкенд
│   ├── 📁 api/                # API эндпоинты
│   │   ├── 📄 auth.py         # Аутентификация
│   │   ├── 📄 projects.py     # Проекты
│   │   ├── 📄 ai.py           # AI интеграция
│   │   └── 📄 health.py       # Health checks
│   ├── 📁 models/             # Pydantic модели
│   │   ├── 📄 requests.py     # Модели запросов
│   │   ├── 📄 responses.py    # Модели ответов
│   │   └── 📄 database.py     # SQLAlchemy модели
│   ├── 📁 services/           # Бизнес-логика
│   │   ├── 📁 implementations/ # Реализации сервисов
│   │   ├── 📄 ai_service.py   # AI сервис
│   │   ├── 📄 rate_limiter.py # Rate limiting
│   │   └── 📄 connection_pool.py # Connection pooling
│   ├── 📁 security/           # Безопасность
│   │   ├── 📄 secrets_manager.py # Управление секретами
│   │   └── 📄 key_rotation.py # Ротация ключей
│   ├── 📁 repositories/       # Repository pattern
│   ├── 📁 middleware/         # Middleware
│   ├── 📁 core/              # Ядро приложения
│   └── 📁 patterns/          # Паттерны (Circuit Breaker)
├── 📁 database/               # База данных
│   ├── 📁 migrations/        # Alembic миграции
│   └── 📄 schema.sql         # SQL схема
├── 📁 config/                # Конфигурация
│   └── 📄 settings.py        # Настройки приложения
├── 📁 tests/                 # Тесты
│   ├── 📁 unit/              # Unit тесты
│   ├── 📁 integration/       # Integration тесты
│   └── 📁 e2e/               # E2E тесты
├── 📁 docs/                  # Документация
│   ├── 📁 architecture/      # Архитектурные решения
│   └── 📁 api/               # API документация
├── 📁 scripts/               # Скрипты
├── 📁 monitoring/            # Мониторинг
├── 📄 .env                   # Переменные окружения
├── 📄 docker-compose.yml     # Docker Compose
├── 📄 Dockerfile             # Docker образ
└── 📄 README.md              # Этот файл
```

### 🔐 Переменные окружения

#### Основные настройки
```env
# ===========================================
# ОСНОВНЫЕ НАСТРОЙКИ
# ===========================================

# Окружение
NODE_ENV=development
ENVIRONMENT=development
DEBUG=true

# Сервер
HOST=0.0.0.0
PORT=8000
FRONTEND_PORT=5173

# ===========================================
# БАЗА ДАННЫХ
# ===========================================

# Supabase (рекомендуется)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key

# Или прямая PostgreSQL
DATABASE_URL=postgresql://user:password@localhost:5432/samokoder

# ===========================================
# БЕЗОПАСНОСТЬ
# ===========================================

# JWT
JWT_SECRET=your-super-secret-jwt-key-here-32-chars
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# API Encryption
API_ENCRYPTION_KEY=your-32-character-secret-key-here
API_ENCRYPTION_SALT=samokoder_salt_2025

# ===========================================
# AI ПРОВАЙДЕРЫ
# ===========================================

# OpenAI
OPENAI_API_KEY=sk-your-openai-key

# Anthropic
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key

# Groq
GROQ_API_KEY=gsk_your-groq-key

# OpenRouter
OPENROUTER_API_KEY=sk-or-your-openrouter-key

# ===========================================
# КЭШИРОВАНИЕ И СЕССИИ
# ===========================================

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your-redis-password

# ===========================================
# МОНИТОРИНГ
# ===========================================

# Sentry
SENTRY_DSN=https://your-sentry-dsn

# Prometheus
ENABLE_METRICS=true
METRICS_PORT=9090

# ===========================================
# ФАЙЛЫ И ХРАНИЛИЩЕ
# ===========================================

# Пути
EXPORT_STORAGE_PATH=./exports
WORKSPACE_STORAGE_PATH=./workspaces
MAX_FILE_SIZE_MB=50

# ===========================================
# RATE LIMITING
# ===========================================

# Лимиты
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# ===========================================
# GPT-PILOT
# ===========================================

# GPT-Pilot интеграция
GPT_PILOT_PATH=./samokoder-core
GPT_PILOT_TIMEOUT=300

# ===========================================
# CORS
# ===========================================

# Разрешенные домены
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,https://yourdomain.com
```

### 🗄️ Настройка базы данных

#### Вариант 1: Supabase (рекомендуется)
```bash
# 1. Создайте проект в Supabase
# 2. Получите URL и ключи
# 3. Выполните SQL скрипт
psql -h your-project.supabase.co -U postgres -d postgres -f database/schema.sql

# 4. Или используйте скрипт
python scripts/setup_supabase.py
```

#### Вариант 2: Локальная PostgreSQL
```bash
# 1. Установите PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# 2. Создайте базу данных
sudo -u postgres createdb samokoder

# 3. Выполните миграции
python -m alembic upgrade head
```

#### Вариант 3: Docker
```bash
# Запустите PostgreSQL в Docker
docker run --name samokoder-postgres \
  -e POSTGRES_DB=samokoder \
  -e POSTGRES_USER=samokoder \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -d postgres:15

# Выполните миграции
python -m alembic upgrade head
```

## 🛠 Технологии

### 🎨 Frontend
| Технология | Версия | Назначение |
|------------|--------|------------|
| **React** | 18.3.1 | UI библиотека |
| **TypeScript** | 5.6.2 | Типизация |
| **Vite** | 5.4.8 | Сборщик |
| **Tailwind CSS** | 3.4.15 | Стилизация |
| **Radix UI** | Latest | UI компоненты |
| **React Router** | 7.0.1 | Маршрутизация |
| **React Query** | 3.39.3 | Управление состоянием |
| **Zustand** | 5.0.8 | State management |
| **Axios** | 1.7.8 | HTTP клиент |
| **Framer Motion** | 12.23.12 | Анимации |

### ⚙️ Backend
| Технология | Версия | Назначение |
|------------|--------|------------|
| **Python** | 3.9+ | Основной язык |
| **FastAPI** | 0.104.1 | Web фреймворк |
| **Uvicorn** | 0.24.0 | ASGI сервер |
| **Pydantic** | 2.8.0+ | Валидация данных |
| **SQLAlchemy** | 2.0+ | ORM |
| **Alembic** | 1.13+ | Миграции БД |
| **Redis** | 5.0.1 | Кэширование |
| **JWT** | 3.3.0 | Аутентификация |
| **Cryptography** | 42.0.0+ | Шифрование |

### 🗄️ База данных
| Технология | Версия | Назначение |
|------------|--------|------------|
| **PostgreSQL** | 15+ | Основная БД |
| **Supabase** | 2.18.1 | Backend-as-a-Service |
| **Row Level Security** | - | Безопасность данных |
| **Real-time** | - | Live updates |

### 🤖 AI и ML
| Технология | Версия | Назначение |
|------------|--------|------------|
| **OpenAI API** | 1.3.7 | GPT модели |
| **Anthropic API** | 0.7.8 | Claude модели |
| **Groq API** | Latest | Быстрые инференсы |
| **OpenRouter** | Latest | Множественные модели |

### 🚀 DevOps
| Технология | Версия | Назначение |
|------------|--------|------------|
| **Docker** | 24+ | Контейнеризация |
| **GitHub Actions** | - | CI/CD |
| **Prometheus** | Latest | Мониторинг |
| **Grafana** | Latest | Визуализация |
| **Sentry** | 1.38.0 | Error tracking |

## 📋 Основные функции

### ✅ Реализовано в v1.0.0

#### 🔐 **Аутентификация и авторизация**
- [x] Регистрация и вход пользователей
- [x] JWT токены с refresh механизмом
- [x] Многофакторная аутентификация (MFA)
- [x] Role-Based Access Control (RBAC)
- [x] Защита от брутфорс атак
- [x] Rate limiting для API

#### 📁 **Управление проектами**
- [x] Создание проектов с AI конфигурацией
- [x] CRUD операции (создание, чтение, обновление, удаление)
- [x] Поиск и фильтрация проектов
- [x] Статусы проектов в реальном времени
- [x] Прогресс генерации с live updates
- [x] Экспорт проектов в ZIP формате

#### 🤖 **AI интеграция**
- [x] Поддержка множественных AI провайдеров
- [x] Fallback механизм при недоступности
- [x] Streaming responses для чата
- [x] Usage tracking и статистика
- [x] GPT-Pilot интеграция
- [x] Контекстное общение с AI

#### 🎨 **Пользовательский интерфейс**
- [x] Современный React UI с TypeScript
- [x] Responsive дизайн (mobile-first)
- [x] WCAG 2.2 AA соответствие доступности
- [x] Core Web Vitals оптимизация
- [x] Lazy loading и code splitting
- [x] Skeleton loading для UX
- [x] Темная/светлая тема

#### 🏗️ **Backend и инфраструктура**
- [x] FastAPI с async/await
- [x] PostgreSQL через Supabase с RLS
- [x] Redis для кэширования и сессий
- [x] Alembic миграции БД
- [x] Connection pooling
- [x] Structured logging
- [x] Health checks для всех сервисов

#### 🚀 **DevOps и мониторинг**
- [x] Docker multi-stage builds
- [x] GitHub Actions CI/CD pipeline
- [x] Blue-Green deployment
- [x] Golden Signals мониторинг
- [x] Automated testing (Unit, Integration, E2E)
- [x] Security scanning в CI/CD

### 🚧 Планируется в v1.1.0

#### 💳 **Монетизация**
- [ ] Система подписок и биллинга
- [ ] Платные тарифы
- [ ] Usage-based pricing
- [ ] Payment gateway интеграция

#### 📊 **Аналитика**
- [ ] Детальная аналитика использования
- [ ] Dashboard с метриками
- [ ] A/B тестирование
- [ ] User behavior tracking

#### 🔄 **Коллаборация**
- [ ] Совместная работа над проектами
- [ ] Real-time collaboration
- [ ] Комментарии и обсуждения
- [ ] Version control для проектов

### 🔮 Планируется в v2.0.0

#### 🏗️ **Микросервисы**
- [ ] Разделение на микросервисы
- [ ] Service mesh (Istio)
- [ ] API Gateway
- [ ] Event-driven architecture

#### 🌍 **Масштабирование**
- [ ] Multi-region deployment
- [ ] CDN интеграция
- [ ] Auto-scaling
- [ ] Load balancing

## 🐛 Устранение неполадок

### 🔧 Общие проблемы

#### Проблема: "ModuleNotFoundError"
```bash
# Решение: Установите зависимости
pip install -r requirements.txt
cd frontend && npm install
```

#### Проблема: "Database connection failed"
```bash
# Решение: Проверьте настройки БД
python scripts/check_database.py

# Или пересоздайте подключение
python scripts/setup_supabase.py
```

#### Проблема: "CORS error"
```bash
# Решение: Проверьте CORS_ORIGINS в .env
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

### 🗄️ Проблемы с базой данных

#### Supabase подключение
```bash
# Проверка подключения
python scripts/test_supabase.py

# Выполнение SQL
python scripts/execute_sql_supabase.py

# Сброс данных
python scripts/reset_supabase.py
```

#### Локальная PostgreSQL
```bash
# Проверка статуса
sudo systemctl status postgresql

# Перезапуск
sudo systemctl restart postgresql

# Проверка подключения
psql -h localhost -U samokoder -d samokoder
```

### 🎨 Проблемы с фронтендом

#### Сборка не работает
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

#### TypeScript ошибки
```bash
# Проверка типов
npm run type-check

# Исправление
npm run lint:fix
```

### ⚙️ Проблемы с бэкендом

#### FastAPI не запускается
```bash
# Проверка зависимостей
pip check

# Переустановка
pip install -r requirements.txt --force-reinstall

# Проверка портов
lsof -i :8000
```

#### Миграции не работают
```bash
# Создание миграции
python -m alembic revision --autogenerate -m "description"

# Применение миграций
python -m alembic upgrade head

# Откат миграций
python -m alembic downgrade -1
```

### 🔐 Проблемы с безопасностью

#### JWT токены не работают
```bash
# Проверка JWT_SECRET
python -c "from config.settings import settings; print(len(settings.jwt_secret))"

# Генерация нового ключа
python scripts/generate_keys.py
```

#### Rate limiting слишком строгий
```bash
# Увеличение лимитов в .env
RATE_LIMIT_PER_MINUTE=120
RATE_LIMIT_PER_HOUR=2000
```

## 📚 Документация

### 📖 Основная документация
- [🚀 Быстрый старт](docs/QUICKSTART.md) - Установка за 5 минут
- [🔧 Установка](docs/INSTALL.md) - Подробная инструкция по установке
- [🚀 Развертывание](docs/DEPLOY.md) - Настройка для продакшена
- [🔐 Безопасность](docs/SECURITY.md) - Руководство по безопасности
- [🧪 Тестирование](docs/TESTING.md) - Запуск тестов
- [📊 Мониторинг](docs/MONITORING.md) - Настройка мониторинга

### 🏗️ Архитектурная документация
- [📋 ADR-001: 12-Factor App](docs/architecture/ADR-001-12-Factor-Compliance.md)
- [📋 ADR-002: Module Boundaries](docs/architecture/ADR-002-Module-Boundaries.md)
- [📋 ADR-003: Database Migrations](docs/architecture/ADR-003-Database-Migrations.md)
- [📋 ADR-004: Security Configuration](docs/architecture/ADR-004-Security-Configuration.md)
- [📋 ADR-005: Minimal Fixes](docs/architecture/ADR-005-Minimal-Fixes.md)

### 🔌 API документация
- [📡 OpenAPI Specification](api/openapi_spec.yaml) - Полная спецификация API
- [📋 API Contracts](tests/test_api_contracts.py) - Контрактные тесты
- [🔄 API Evolution](api/evolution_plan.md) - План эволюции API
- [⚠️ Deprecated Fields](api/deprecated_fields.yaml) - Устаревшие поля

### 🧪 Тестирование
- [🧪 Unit Tests](tests/unit/) - Модульные тесты
- [🔗 Integration Tests](tests/integration/) - Интеграционные тесты
- [🎭 E2E Tests](tests/e2e/) - End-to-end тесты
- [🔒 Security Tests](tests/security/) - Тесты безопасности
- [⚡ Performance Tests](tests/performance/) - Тесты производительности

### 📊 Отчеты и аудиты
- [📊 Improvements Report](IMPROVEMENTS_REPORT.md) - Отчет об улучшениях
- [🔒 Security Audit](SECURITY_AUDIT_REPORT.md) - Аудит безопасности
- [🧪 QA Testing](QA_REGRESSION_TESTING_REPORT.md) - QA тестирование
- [⚡ Performance](PERFORMANCE_OPTIMIZATION_REPORT.md) - Оптимизация производительности
- [🚀 DevOps](DEVOPS_SRE_REPORT.md) - DevOps готовность
- [📡 API Owner](API_OWNER_REPORT.md) - API управление
- [♿ Accessibility](accessibility/accessibility_verification_report.md) - Доступность
- [🎯 Product Owner](PRODUCT_OWNER_FINAL_REPORT.md) - Финальный отчет
- [🚀 Release Manager](RELEASE_MANAGER_REPORT.md) - Управление релизами

## 🤝 Вклад в проект

### 🚀 Быстрый старт для разработчиков

1. **Форкните репозиторий**
   ```bash
   git clone https://github.com/your-username/samokoder.git
   cd samokoder
   ```

2. **Создайте ветку для функции**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Установите зависимости**
   ```bash
   # Backend
   pip install -r requirements.txt
   pip install -r requirements-dev.txt

   # Frontend
   cd frontend
   npm install
   ```

4. **Запустите тесты**
   ```bash
   # Все тесты
   make test

   # Только unit тесты
   make test-unit

   # Только e2e тесты
   make test-e2e
   ```

5. **Внесите изменения и создайте PR**
   ```bash
   git add .
   git commit -m "feat: add your feature"
   git push origin feature/your-feature-name
   ```

### 📋 Стандарты разработки

#### 🐍 Python (Backend)
- **PEP 8** стиль кода
- **Type hints** для всех функций
- **Docstrings** для всех классов и методов
- **Pytest** для тестирования
- **Black** для форматирования
- **isort** для сортировки импортов

#### ⚛️ TypeScript (Frontend)
- **ESLint** конфигурация
- **Prettier** форматирование
- **TypeScript strict mode**
- **Jest** для тестирования
- **React Testing Library** для компонентов

#### 📝 Git workflow
- **Conventional Commits** для сообщений
- **Feature branches** для новых функций
- **Pull Request** для всех изменений
- **Code review** обязательно
- **CI/CD** проверки

### 🧪 Тестирование

#### Запуск тестов
```bash
# Все тесты
make test

# Unit тесты
make test-unit

# Integration тесты
make test-integration

# E2E тесты
make test-e2e

# Security тесты
make test-security

# Performance тесты
make test-performance
```

#### Покрытие кода
```bash
# Backend coverage
pytest --cov=backend --cov-report=html

# Frontend coverage
cd frontend && npm run test:coverage
```

### 🔍 Code Review

#### Чек-лист для PR
- [ ] Код соответствует стандартам
- [ ] Тесты написаны и проходят
- [ ] Документация обновлена
- [ ] Безопасность проверена
- [ ] Производительность не пострадала
- [ ] Accessibility соблюдена
- [ ] Breaking changes документированы

## 📄 Лицензия

MIT License - см. [LICENSE](LICENSE)

## 🆘 Поддержка

### 📞 Получение помощи

1. **Проверьте документацию** - начните с [быстрого старта](docs/QUICKSTART.md)
2. **Поиск в Issues** - возможно, ваша проблема уже решена
3. **Создайте Issue** - опишите проблему подробно
4. **Discord** - присоединяйтесь к нашему сообществу
5. **Email** - support@samokoder.com

### 🐛 Сообщение об ошибках

При создании Issue укажите:
- **Версию** приложения
- **Операционную систему**
- **Шаги воспроизведения**
- **Ожидаемое поведение**
- **Фактическое поведение**
- **Логи ошибок**

### 💡 Предложения функций

Мы приветствуем предложения! При создании Issue:
- **Опишите проблему** которую решает функция
- **Предложите решение**
- **Укажите приоритет**
- **Приложите mockups** если возможно

---

## 🎯 Статус проекта

**Версия**: 1.0.0  
**Статус**: ✅ **Production Ready**  
**Последнее обновление**: 2025-09-10  
**Следующий релиз**: v1.1.0 (Q4 2025)  

### 🏆 Достижения v1.0.0
- ✅ **Первый стабильный релиз**
- ✅ **Полная функциональность**
- ✅ **Безопасность ASVS Level 2**
- ✅ **Производительность оптимизирована**
- ✅ **Доступность WCAG 2.2 AA**
- ✅ **95% test coverage**
- ✅ **CI/CD pipeline готов**
- ✅ **Мониторинг настроен**

---

**Создано с ❤️ командой Самокодер**  
**© 2025 Samokoder. Все права защищены.**