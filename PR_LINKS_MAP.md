# 🔗 Карта ссылок для Pull Request - Самокодер v1.0.0

> **Полная карта всех ссылок и ресурсов**  
> Для удобной навигации по проекту в PR

## 📋 Содержание

- [Основные ссылки](#-основные-ссылки)
- [Документация](#-документация)
- [Конфигурация](#-конфигурация)
- [Тестирование](#-тестирование)
- [Мониторинг](#-мониторинг)
- [Безопасность](#-безопасность)
- [DevOps](#-devops)
- [API](#-api)
- [Отчеты](#-отчеты)

## 🎯 Основные ссылки

### 📖 Главная документация
- [📚 README.md](README.md) - Главная документация проекта
- [🚀 Быстрый старт](docs/QUICKSTART.md) - Установка за 5 минут
- [🔧 Подробная установка](docs/INSTALL.md) - Полное руководство по установке
- [❓ FAQ](FAQ.md) - Часто задаваемые вопросы

### 🏗️ Архитектура
- [📋 ADR-001: 12-Factor App](docs/architecture/ADR-001-12-Factor-Compliance.md)
- [📋 ADR-002: Module Boundaries](docs/architecture/ADR-002-Module-Boundaries.md)
- [📋 ADR-003: Database Migrations](docs/architecture/ADR-003-Database-Migrations.md)
- [📋 ADR-004: Security Configuration](docs/architecture/ADR-004-Security-Configuration.md)
- [📋 ADR-005: Minimal Fixes](docs/architecture/ADR-005-Minimal-Fixes.md)

## 📚 Документация

### 🚀 Развертывание и операции
- [🚀 Развертывание](docs/DEPLOY.md) - Настройка для продакшена
- [🔧 Операции](docs/OPERATIONS.md) - Руководство по эксплуатации
- [🗄️ Миграции](docs/MIGRATIONS.md) - Управление миграциями БД
- [📊 Мониторинг](docs/MONITORING.md) - Настройка мониторинга
- [🔐 Безопасность](docs/SECURITY.md) - Руководство по безопасности
- [🧪 Тестирование](docs/TESTING.md) - Запуск тестов

### 🎨 Frontend
- [⚛️ Frontend README](frontend/README.md) - Документация фронтенда
- [🎨 UI Components](frontend/src/components/) - UI компоненты
- [♿ Accessibility](frontend/src/components/accessibility/) - Компоненты доступности
- [🎣 Hooks](frontend/src/hooks/) - Custom React hooks
- [📱 Pages](frontend/src/pages/) - Страницы приложения

### ⚙️ Backend
- [🐍 Backend README](backend/README.md) - Документация бэкенда
- [🔌 API Endpoints](backend/api/) - API эндпоинты
- [📊 Models](backend/models/) - Pydantic модели
- [🛠️ Services](backend/services/) - Бизнес-логика
- [🔐 Security](backend/security/) - Безопасность
- [🏗️ Core](backend/core/) - Ядро приложения

## ⚙️ Конфигурация

### 🔧 Основные конфиги
- [📄 .env.example](.env.example) - Пример конфигурации
- [⚙️ Settings](config/settings.py) - Настройки приложения
- [🐳 Docker Compose](docker-compose.yml) - Docker конфигурация
- [🐳 Dockerfile](Dockerfile) - Docker образ
- [📦 Requirements](requirements.txt) - Python зависимости
- [📦 Package.json](frontend/package.json) - Node.js зависимости

### 🗄️ База данных
- [🗄️ Schema](database/schema.sql) - SQL схема БД
- [🔄 Migrations](database/migrations/) - Alembic миграции
- [📊 Initial Migration](database/migrations/versions/9571625a63ee_initial_schema_migration.py) - Начальная миграция

### 🔧 Скрипты
- [🚀 Start Script](scripts/start_dev.sh) - Скрипт запуска
- [🧪 Test Reproducibility](scripts/test_reproducibility.sh) - Тест воспроизводимости
- [🔑 Key Generator](scripts/generate_keys_simple.py) - Генератор ключей
- [📊 Database Setup](scripts/setup_supabase.py) - Настройка БД

## 🧪 Тестирование

### 📊 Тестовые файлы
- [🧪 Unit Tests](tests/) - Основные тесты
- [🔗 Integration Tests](tests/integration/) - Интеграционные тесты
- [🔒 Security Tests](tests/security/) - Тесты безопасности
- [⚡ Performance Tests](tests/performance/) - Тесты производительности
- [🎭 E2E Tests](tests/e2e/) - End-to-end тесты

### 🔧 Конфигурация тестов
- [⚙️ Pytest Config](pytest.ini) - Конфигурация pytest
- [🔧 Test Config](conftest.py) - Общая конфигурация тестов
- [🚀 Test Runner](run_tests.py) - Запуск тестов

### 📋 Тестовые отчеты
- [📊 Test Execution Report](TEST_EXECUTION_REPORT.md) - Отчет о выполнении тестов
- [🧪 QA Regression Testing](QA_REGRESSION_TESTING_REPORT.md) - QA регрессионное тестирование

## 📊 Мониторинг

### 📈 Конфигурация мониторинга
- [📊 Prometheus Config](monitoring/prometheus/) - Конфигурация Prometheus
- [🚨 Alertmanager Config](monitoring/alertmanager/) - Конфигурация алертов
- [📊 Grafana Dashboard](monitoring/grafana/) - Дашборды Grafana
- [📊 Golden Signals](monitoring/golden_signals_config.yml) - Golden Signals

### 📊 Метрики и алерты
- [📊 Metrics](backend/monitoring/) - Метрики приложения
- [🚨 Alerts](monitoring/alertmanager_config.yml) - Правила алертов
- [📊 Dashboard](monitoring/grafana_dashboard.json) - Grafana дашборд

## 🔐 Безопасность

### 🛡️ Security патчи
- [🔐 ASVS Auth Fixes](security_patches/asvs_v2_auth_p0_fixes.py) - ASVS аутентификация
- [🔐 ASVS Sessions Fixes](security_patches/asvs_v3_sessions_p0_fixes.py) - ASVS сессии
- [🔐 ASVS Access Control](security_patches/asvs_v4_access_control_p0_fixes.py) - ASVS контроль доступа
- [🔐 ASVS Validation](security_patches/asvs_v5_validation_p0_fixes.py) - ASVS валидация
- [🔐 ASVS Error Handling](security_patches/asvs_v7_errors_logging_p0_fixes.py) - ASVS обработка ошибок
- [🔐 ASVS Configuration](security_patches/asvs_v10_configuration_p0_fixes.py) - ASVS конфигурация
- [🔐 ASVS API Security](security_patches/asvs_v12_api_security_p0_fixes.py) - ASVS API безопасность

### 🧪 Security тесты
- [🧪 Auth Tests](tests/test_security_asvs_v2_auth.py) - Тесты аутентификации
- [🧪 Sessions Tests](tests/test_security_asvs_v3_sessions.py) - Тесты сессий
- [🧪 Access Control Tests](tests/test_security_asvs_v4_access_control.py) - Тесты контроля доступа
- [🧪 Validation Tests](tests/test_security_asvs_v5_validation.py) - Тесты валидации
- [🧪 Error Handling Tests](tests/test_security_asvs_v7_errors_logging.py) - Тесты обработки ошибок
- [🧪 Configuration Tests](tests/test_security_asvs_v10_configuration.py) - Тесты конфигурации
- [🧪 API Security Tests](tests/test_security_asvs_v12_api_security.py) - Тесты API безопасности

### 📊 Security отчеты
- [🔒 Security Audit Report](SECURITY_AUDIT_REPORT.md) - Отчет аудита безопасности
- [🔒 Security Fixes](SECURITY_FIXES.md) - Исправления безопасности

## 🚀 DevOps

### 🔄 CI/CD
- [🔄 CI Pipeline](.github/workflows/ci.yml) - CI пайплайн
- [🔒 Security Pipeline](.github/workflows/security.yml) - Security пайплайн
- [📦 Dependency Updates](.github/workflows/dependency-update.yml) - Обновления зависимостей

### 🐳 Docker
- [🐳 Dockerfile](Dockerfile) - Docker образ
- [🐳 Docker Compose](docker-compose.yml) - Docker Compose
- [🐳 Production Docker](docker-compose.prod.yml) - Production Docker

### 📋 DevOps отчеты
- [🚀 DevOps SRE Report](DEVOPS_SRE_REPORT.md) - DevOps SRE отчет
- [📊 Release Readiness](devops/release_readiness_check.md) - Готовность к релизу
- [📋 Release Plan](devops/release_plan.md) - План релиза
- [✅ Post Deploy Checklist](devops/post_deploy_verification_checklist.md) - Чек-лист пост-деплоя

## 🔌 API

### 📡 API документация
- [📡 OpenAPI Spec](api/openapi_spec.yaml) - OpenAPI спецификация
- [📋 API Contracts](tests/test_api_contracts.py) - Контрактные тесты
- [🔄 API Evolution](api/evolution_plan.md) - План эволюции API
- [⚠️ Deprecated Fields](api/deprecated_fields.yaml) - Устаревшие поля

### 🔌 API эндпоинты
- [🔐 Auth API](backend/api/auth.py) - Аутентификация
- [📁 Projects API](backend/api/projects.py) - Проекты
- [🤖 AI API](backend/api/ai.py) - AI интеграция
- [❤️ Health API](backend/api/health.py) - Health checks

### 📊 API модели
- [📥 Request Models](backend/models/requests.py) - Модели запросов
- [📤 Response Models](backend/models/responses.py) - Модели ответов
- [🗄️ Database Models](backend/models/database.py) - Модели БД

## 📊 Отчеты

### 🎯 Основные отчеты
- [📊 Improvements Report](IMPROVEMENTS_REPORT.md) - Отчет об улучшениях
- [✅ Verification Report](VERIFICATION_REPORT.md) - Отчет верификации
- [🏗️ Architectural Fixes](ARCHITECTURAL_FIXES_REPORT.md) - Архитектурные исправления
- [📋 Code Review Report](CODE_REVIEW_REPORT.md) - Отчет код-ревью

### 🎯 Специализированные отчеты
- [🧪 QA Regression Testing](QA_REGRESSION_TESTING_REPORT.md) - QA регрессионное тестирование
- [⚡ Performance Optimization](PERFORMANCE_OPTIMIZATION_REPORT.md) - Оптимизация производительности
- [🚀 DevOps SRE](DEVOPS_SRE_REPORT.md) - DevOps SRE отчет
- [📡 API Owner](API_OWNER_REPORT.md) - API Owner отчет
- [♿ Accessibility](accessibility/accessibility_verification_report.md) - Отчет доступности
- [🎯 Product Owner](PRODUCT_OWNER_FINAL_REPORT.md) - Финальный отчет Product Owner
- [🚀 Release Manager](RELEASE_MANAGER_REPORT.md) - Отчет Release Manager

### 🎯 Технические отчеты
- [🔒 Security Audit](SECURITY_AUDIT_REPORT.md) - Аудит безопасности
- [♿ WCAG Audit](accessibility/wcag_audit_report.md) - WCAG аудит
- [⚡ Web Vitals Analysis](performance/current_web_vitals_analysis.md) - Анализ Web Vitals
- [📊 Before/After Comparison](performance/before_after_comparison.md) - Сравнение до/после

## 🎨 Frontend компоненты

### 🧩 UI компоненты
- [🎨 Button](frontend/src/components/ui/button.tsx) - Кнопка
- [📝 Input](frontend/src/components/ui/input.tsx) - Поле ввода
- [🏷️ Label](frontend/src/components/ui/label.tsx) - Метка
- [📋 Card](frontend/src/components/ui/card.tsx) - Карточка
- [📊 Progress](frontend/src/components/ui/progress.tsx) - Прогресс бар

### ♿ Accessibility компоненты
- [🔗 Skip Link](frontend/src/components/accessibility/SkipLink.tsx) - Пропуск ссылок
- [📢 Error Announcer](frontend/src/components/accessibility/ErrorAnnouncer.tsx) - Анонсер ошибок
- [🎯 Focus Management](frontend/src/hooks/useFocusManagement.ts) - Управление фокусом
- [⌨️ Keyboard Shortcuts](frontend/src/hooks/useKeyboardShortcuts.ts) - Горячие клавиши
- [📱 Screen Reader Support](frontend/src/components/accessibility/ScreenReaderSupport.tsx) - Поддержка скрин-ридеров

### 📱 Страницы
- [🏠 Home](frontend/src/pages/Home.tsx) - Главная страница
- [📊 Dashboard](frontend/src/pages/Dashboard.tsx) - Дашборд
- [💼 Workspace](frontend/src/pages/Workspace.tsx) - Рабочее пространство
- [⚙️ Settings](frontend/src/pages/Settings.tsx) - Настройки
- [🔐 Login](frontend/src/pages/Login.tsx) - Вход
- [📝 Register](frontend/src/pages/Register.tsx) - Регистрация

## 🛠️ Backend сервисы

### 🔧 Основные сервисы
- [🤖 AI Service](backend/services/ai_service.py) - AI сервис
- [🔄 Rate Limiter](backend/services/rate_limiter.py) - Rate limiting
- [🔗 Connection Pool](backend/services/connection_pool.py) - Пул соединений
- [📄 Pagination](backend/services/pagination.py) - Пагинация
- [🔄 Migration Manager](backend/services/migration_manager.py) - Менеджер миграций

### 🔐 Security сервисы
- [🔑 Secrets Manager](backend/security/secrets_manager.py) - Управление секретами
- [🔄 Key Rotation](backend/security/key_rotation.py) - Ротация ключей
- [🔐 Encryption](backend/services/encryption.py) - Шифрование

### 🏗️ Core компоненты
- [🏗️ Container](backend/core/container.py) - DI контейнер
- [⚙️ Config](backend/core/config.py) - Конфигурация
- [❌ Exceptions](backend/core/exceptions.py) - Исключения
- [🔧 Setup](backend/core/setup.py) - Настройка

## 📋 Полезные ссылки

### 🔗 Внешние ресурсы
- [📚 FastAPI Docs](https://fastapi.tiangolo.com/) - Документация FastAPI
- [⚛️ React Docs](https://reactjs.org/docs/) - Документация React
- [🎨 Tailwind CSS](https://tailwindcss.com/docs) - Документация Tailwind
- [🗄️ Supabase Docs](https://supabase.com/docs) - Документация Supabase
- [🐳 Docker Docs](https://docs.docker.com/) - Документация Docker

### 🛠️ Инструменты разработки
- [🧪 Pytest](https://docs.pytest.org/) - Тестирование Python
- [⚛️ Jest](https://jestjs.io/docs/) - Тестирование JavaScript
- [🔍 ESLint](https://eslint.org/docs/) - Линтинг JavaScript
- [🎨 Prettier](https://prettier.io/docs/) - Форматирование кода
- [📊 TypeScript](https://www.typescriptlang.org/docs/) - Документация TypeScript

### 🔐 Безопасность
- [🛡️ ASVS](https://owasp.org/www-project-application-security-verification-standard/) - Application Security Verification Standard
- [♿ WCAG](https://www.w3.org/WAI/WCAG21/quickref/) - Web Content Accessibility Guidelines
- [🔒 OWASP](https://owasp.org/) - Open Web Application Security Project

---

## 🎯 Быстрая навигация

### 🚀 Для новых разработчиков
1. [📚 README](README.md) - Начните здесь
2. [🚀 Быстрый старт](docs/QUICKSTART.md) - Установка за 5 минут
3. [❓ FAQ](FAQ.md) - Ответы на вопросы
4. [🔧 Подробная установка](docs/INSTALL.md) - Полная установка

### 🔧 Для DevOps
1. [🚀 Развертывание](docs/DEPLOY.md) - Настройка продакшена
2. [🔧 Операции](docs/OPERATIONS.md) - Эксплуатация
3. [📊 Мониторинг](docs/MONITORING.md) - Мониторинг
4. [🚀 DevOps SRE Report](DEVOPS_SRE_REPORT.md) - DevOps отчет

### 🧪 Для QA
1. [🧪 Тестирование](docs/TESTING.md) - Запуск тестов
2. [📊 QA Regression Testing](QA_REGRESSION_TESTING_REPORT.md) - QA отчет
3. [🧪 Test Execution Report](TEST_EXECUTION_REPORT.md) - Отчет тестов

### 🔐 Для Security
1. [🔐 Безопасность](docs/SECURITY.md) - Руководство по безопасности
2. [🔒 Security Audit Report](SECURITY_AUDIT_REPORT.md) - Аудит безопасности
3. [🛡️ Security Patches](security_patches/) - Патчи безопасности

### 📡 Для API разработчиков
1. [📡 OpenAPI Spec](api/openapi_spec.yaml) - API спецификация
2. [📋 API Contracts](tests/test_api_contracts.py) - Контрактные тесты
3. [📡 API Owner Report](API_OWNER_REPORT.md) - API отчет

---

**Создано с ❤️ командой Самокодер**  
**© 2025 Samokoder. Все права защищены.**