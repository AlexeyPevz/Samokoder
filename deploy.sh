#!/bin/bash
set -euo pipefail  # Exit on error, undefined variable, pipe failure

echo "🚀 Samokoder SaaS - Развертывание (BYOK Модель)"
echo "=============================================="

# Проверка наличия .env файла
if [ ! -f .env ]; then
    echo "❌ Файл .env не найден. Создайте его из .env.example"
    exit 1
fi

# Загрузка переменных окружения
set -a
source .env
set +a

echo "✅ Проверка переменных окружения..."

# Проверка обязательных переменных
required_vars=("SECRET_KEY" "APP_SECRET_KEY" "DATABASE_URL")
for var in "${required_vars[@]}"; do
    if [ -z "${!var:-}" ]; then
        echo "❌ Обязательная переменная $var не установлена в .env"
        exit 1
    fi
done

# Проверка наличия Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker не установлен"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose не установлен"
    exit 1
fi

# Определяем команду docker compose
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

echo "✅ Docker установлен"

# Остановка существующих контейнеров
echo "🛑 Остановка существующих контейнеров..."
$DOCKER_COMPOSE down || true

# Запуск инфраструктуры
echo "🐳 Запуск базы данных и Redis..."
$DOCKER_COMPOSE up -d db redis

# Ожидание готовности БД
echo "⏳ Ожидание готовности базы данных..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec samokoder-postgres pg_isready -U samokoder -d samokoder 2>/dev/null; then
        echo "✅ База данных готова"
        break
    fi
    attempt=$((attempt + 1))
    if [ $attempt -eq $max_attempts ]; then
        echo "❌ Не удалось подключиться к базе данных после $max_attempts попыток"
        exit 1
    fi
    sleep 2
done

# Применение миграций
echo "🔄 Применение миграций базы данных..."
if [ -f "alembic.ini" ]; then
    alembic upgrade head || {
        echo "❌ Ошибка при применении миграций"
        exit 1
    }
else
    echo "⚠️  alembic.ini не найден, пропускаем миграции"
fi

# Установка Python зависимостей
echo "📦 Установка Python зависимостей..."
pip install -r requirements.txt || {
    echo "❌ Ошибка при установке Python зависимостей"
    exit 1
}

# Установка Node.js зависимостей (только если папка frontend существует)
if [ -d "frontend" ]; then
    echo "📦 Установка Node.js зависимостей..."
    (cd frontend && npm ci) || {
        echo "❌ Ошибка при установке Node.js зависимостей"
        exit 1
    }

    # Сборка frontend
    echo "🔨 Сборка frontend..."
    (cd frontend && npm run build) || {
        echo "❌ Ошибка при сборке frontend"
        exit 1
    }
else
    echo "⚠️  Папка frontend не найдена, пропускаем сборку"
fi

# Запуск API через Docker Compose
echo "🚀 Запуск всех сервисов..."
$DOCKER_COMPOSE up -d

# Ожидание запуска API
echo "⏳ Ожидание запуска API сервера..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        echo "✅ API работает корректно"
        break
    fi
    attempt=$((attempt + 1))
    if [ $attempt -eq $max_attempts ]; then
        echo "❌ API не отвечает после $max_attempts попыток"
        echo "📋 Логи API:"
        $DOCKER_COMPOSE logs api
        exit 1
    fi
    sleep 2
done

echo ""
echo "🎉 Развертывание завершено успешно!"
echo "=================================="
echo "📱 Frontend: http://localhost:5173"
echo "🔌 API: http://localhost:8000"
echo "📊 Health check: http://localhost:8000/health"
echo "📈 Metrics: http://localhost:8000/metrics"
echo "📊 Grafana: http://localhost:3000 (admin/admin)"
echo "🔥 Prometheus: http://localhost:9090"
echo ""
echo "📝 Bring Your Own Key (BYOK) Модель:"
echo "   • Платформа работает без предустановленных API ключей"
echo "   • Пользователи добавляют свои ключи в настройках"
echo "   • Вы монетизируете платформу, а не API ключи"
echo ""
echo "📝 Следующие шаги:"
echo "1. Откройте http://localhost:5173 в браузере"
echo "2. Зарегистрируйте нового пользователя"
echo "3. В настройках профиля добавьте API ключи от:"
echo "   - OpenAI (https://platform.openai.com/api-keys)"
echo "   - Anthropic (https://console.anthropic.com/settings/keys)"
echo "   - OpenRouter (https://openrouter.ai/keys)"
echo "4. Создайте первый проект"
echo ""
echo "📋 Полезные команды:"
echo "   Просмотр логов: $DOCKER_COMPOSE logs -f"
echo "   Остановка: $DOCKER_COMPOSE down"
echo "   Перезапуск: $DOCKER_COMPOSE restart"
