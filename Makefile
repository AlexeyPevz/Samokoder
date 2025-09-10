# Makefile для проекта Самокодер

.PHONY: help install install-dev test test-unit test-integration test-security lint format clean build run dev setup pre-commit

# Переменные
PYTHON := python3
PIP := pip3
NPM := npm
DOCKER := docker
DOCKER_COMPOSE := docker-compose

# Цвета для вывода
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Показать справку
	@echo "$(BLUE)Доступные команды:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Установить зависимости
	@echo "$(BLUE)📦 Установка зависимостей...$(NC)"
	$(PIP) install -r requirements.txt
	cd frontend && $(NPM) install

install-dev: ## Установить зависимости для разработки
	@echo "$(BLUE)📦 Установка зависимостей для разработки...$(NC)"
	$(PIP) install -r requirements-dev.txt
	cd frontend && $(NPM) install
	pre-commit install

setup: install-dev ## Настройка проекта для разработки
	@echo "$(BLUE)🔧 Настройка проекта...$(NC)"
	cp .env.example .env
	@echo "$(GREEN)✅ Проект настроен! Отредактируйте .env файл$(NC)"

test: ## Запустить все тесты
	@echo "$(BLUE)🧪 Запуск всех тестов...$(NC)"
	$(PYTHON) -m pytest tests/ -v --cov=backend --cov-report=html --cov-report=term

test-unit: ## Запустить unit тесты
	@echo "$(BLUE)🧪 Запуск unit тестов...$(NC)"
	$(PYTHON) -m pytest tests/ -m unit -v

test-integration: ## Запустить integration тесты
	@echo "$(BLUE)🔗 Запуск integration тестов...$(NC)"
	$(PYTHON) -m pytest tests/ -m integration -v

test-security: ## Запустить security тесты
	@echo "$(BLUE)🔒 Запуск security тестов...$(NC)"
	$(PYTHON) -m pytest tests/ -m security -v

test-frontend: ## Запустить frontend тесты
	@echo "$(BLUE)🧪 Запуск frontend тестов...$(NC)"
	cd frontend && $(NPM) test

lint: ## Проверить код линтерами
	@echo "$(BLUE)🔍 Проверка кода...$(NC)"
	flake8 backend/ tests/ --max-line-length=100 --ignore=E203,W503
	black --check backend/ tests/
	isort --check-only backend/ tests/
	mypy backend/ --ignore-missing-imports
	cd frontend && $(NPM) run lint

format: ## Форматировать код
	@echo "$(BLUE)🎨 Форматирование кода...$(NC)"
	black backend/ tests/
	isort backend/ tests/
	cd frontend && $(NPM) run format

security: ## Проверить безопасность
	@echo "$(BLUE)🔒 Проверка безопасности...$(NC)"
	bandit -r backend/
	safety check
	semgrep --config=auto backend/

clean: ## Очистить временные файлы
	@echo "$(BLUE)🧹 Очистка...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	rm -rf frontend/dist/ frontend/node_modules/
	rm -rf test_reports/ .benchmarks/

build: ## Собрать проект
	@echo "$(BLUE)🏗️ Сборка проекта...$(NC)"
	cd frontend && $(NPM) run build
	$(DOCKER) build -t samokoder:latest .

run: ## Запустить приложение
	@echo "$(BLUE)🚀 Запуск приложения...$(NC)"
	$(PYTHON) -m uvicorn backend.main_improved:app --host 0.0.0.0 --port 8000 --reload

dev: ## Запустить в режиме разработки
	@echo "$(BLUE)🚀 Запуск в режиме разработки...$(NC)"
	$(DOCKER_COMPOSE) up --build

docker-build: ## Собрать Docker образ
	@echo "$(BLUE)🐳 Сборка Docker образа...$(NC)"
	$(DOCKER) build -t samokoder:latest .

docker-run: ## Запустить в Docker
	@echo "$(BLUE)🐳 Запуск в Docker...$(NC)"
	$(DOCKER) run -p 8000:8000 --env-file .env samokoder:latest

docker-compose-up: ## Запустить через Docker Compose
	@echo "$(BLUE)🐳 Запуск через Docker Compose...$(NC)"
	$(DOCKER_COMPOSE) up -d

docker-compose-down: ## Остановить Docker Compose
	@echo "$(BLUE)🐳 Остановка Docker Compose...$(NC)"
	$(DOCKER_COMPOSE) down

pre-commit: ## Запустить pre-commit проверки
	@echo "$(BLUE)🔍 Запуск pre-commit проверок...$(NC)"
	pre-commit run --all-files

migrate: ## Запустить миграции базы данных
	@echo "$(BLUE)🗄️ Запуск миграций...$(NC)"
	$(PYTHON) -m alembic upgrade head

migrate-create: ## Создать новую миграцию
	@echo "$(BLUE)🗄️ Создание миграции...$(NC)"
	@read -p "Введите название миграции: " name; \
	$(PYTHON) -m alembic revision --autogenerate -m "$$name"

seed: ## Заполнить базу тестовыми данными
	@echo "$(BLUE)🌱 Заполнение базы тестовыми данными...$(NC)"
	$(PYTHON) scripts/seed_database.py

docs: ## Сгенерировать документацию
	@echo "$(BLUE)📚 Генерация документации...$(NC)"
	cd docs && make html

coverage: ## Показать покрытие кода
	@echo "$(BLUE)📊 Покрытие кода...$(NC)"
	$(PYTHON) -m pytest tests/ --cov=backend --cov-report=html
	@echo "$(GREEN)Откройте htmlcov/index.html в браузере$(NC)"

performance: ## Запустить performance тесты
	@echo "$(BLUE)⚡ Performance тесты...$(NC)"
	$(PYTHON) -m pytest tests/ -m performance --benchmark-only

load-test: ## Запустить нагрузочные тесты
	@echo "$(BLUE)⚡ Нагрузочные тесты...$(NC)"
	locust -f tests/load_test.py --host=http://localhost:8000

deploy-staging: ## Деплой на staging
	@echo "$(BLUE)🚀 Деплой на staging...$(NC)"
	# Здесь должна быть логика деплоя на staging

deploy-production: ## Деплой на production
	@echo "$(BLUE)🚀 Деплой на production...$(NC)"
	# Здесь должна быть логика деплоя на production

backup: ## Создать бэкап базы данных
	@echo "$(BLUE)💾 Создание бэкапа...$(NC)"
	pg_dump $DATABASE_URL > backup_$(shell date +%Y%m%d_%H%M%S).sql

restore: ## Восстановить базу данных из бэкапа
	@echo "$(BLUE)💾 Восстановление из бэкапа...$(NC)"
	@read -p "Введите путь к файлу бэкапа: " backup_file; \
	psql $DATABASE_URL < $$backup_file

logs: ## Показать логи
	@echo "$(BLUE)📋 Логи приложения...$(NC)"
	$(DOCKER_COMPOSE) logs -f

status: ## Показать статус сервисов
	@echo "$(BLUE)📊 Статус сервисов...$(NC)"
	$(DOCKER_COMPOSE) ps

health: ## Проверить здоровье приложения
	@echo "$(BLUE)🏥 Проверка здоровья...$(NC)"
	curl -f http://localhost:8000/health || echo "$(RED)❌ Приложение недоступно$(NC)"

# Команды для CI/CD
ci-test: test lint security ## Полный набор тестов для CI
	@echo "$(GREEN)✅ Все проверки пройдены!$(NC)"

ci-build: clean build ## Сборка для CI
	@echo "$(GREEN)✅ Сборка завершена!$(NC)"

# Команды для разработки
dev-setup: setup pre-commit ## Полная настройка для разработки
	@echo "$(GREEN)✅ Проект готов к разработке!$(NC)"

quick-test: test-unit lint ## Быстрые тесты для разработки
	@echo "$(GREEN)✅ Быстрые тесты пройдены!$(NC)"

# Команды для мониторинга
monitor: ## Запустить мониторинг
	@echo "$(BLUE)📊 Запуск мониторинга...$(NC)"
	$(DOCKER_COMPOSE) -f docker-compose.monitoring.yml up -d

metrics: ## Показать метрики
	@echo "$(BLUE)📊 Метрики приложения...$(NC)"
	curl http://localhost:8000/metrics

# Команды для отладки
debug: ## Запустить в режиме отладки
	@echo "$(BLUE)🐛 Запуск в режиме отладки...$(NC)"
	$(PYTHON) -m uvicorn backend.main_improved:app --host 0.0.0.0 --port 8000 --reload --log-level debug

shell: ## Открыть Python shell
	@echo "$(BLUE)🐍 Python shell...$(NC)"
	$(PYTHON) -c "import backend; import IPython; IPython.embed()"

# Команды для обновления зависимостей
update-deps: ## Обновить зависимости
	@echo "$(BLUE)📦 Обновление зависимостей...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt --upgrade
	cd frontend && $(NPM) update

check-deps: ## Проверить устаревшие зависимости
	@echo "$(BLUE)📦 Проверка зависимостей...$(NC)"
	$(PIP) list --outdated
	cd frontend && $(NPM) outdated