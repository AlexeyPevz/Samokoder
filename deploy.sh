#!/bin/bash

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

# Проверка наличия Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker не установлен"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose не установлен"
    exit 1
fi

echo "✅ Docker установлен"

# Остановка существующих контейнеров
echo "🛑 Остановка существующих контейнеров..."
docker-compose down

# Запуск инфраструктуры
echo "🐳 Запуск базы данных и Redis..."
docker-compose up -d db redis

# Ожидание готовности БД
echo "⏳ Ожидание готовности базы данных..."
sleep 10

# Проверка подключения к БД
if docker exec samokoder-postgres pg_isready -U samokoder -d samokoder; then
    echo "✅ База данных готова"
else
    echo "❌ Не удалось подключиться к базе данных"
    exit 1
fi

# Применение миграций
echo "🔄 Применение миграций базы данных..."
python init_db.py

# Установка Python зависимостей
echo "📦 Установка Python зависимостей..."
pip install -r requirements.txt

# Установка Node.js зависимостей
echo "📦 Установка Node.js зависимостей..."
cd frontend && npm install && cd ..

# Сборка frontend
echo "🔨 Сборка frontend..."
cd frontend && npm run build && cd ..

# Запуск API
echo "🚀 Запуск API сервера..."
uvicorn samokoder.api.main:app --host 0.0.0.0 --port 8000 &
API_PID=$!

# Ожидание запуска API
sleep 5

# Проверка API
echo "🔍 Проверка работоспособности API..."
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    echo "✅ API работает корректно"
else
    echo "❌ API не отвечает"
    kill $API_PID
    exit 1
fi

echo ""
echo "🎉 Развертывание завершено успешно!"
echo "=================================="
echo "📱 Frontend: http://localhost:3000"
echo "🔌 API: http://localhost:8000"
echo "📊 Health check: http://localhost:8000/health"
echo ""
echo "📝 Bring Your Own Key (BYOK) Модель:"
echo "   • Платформа работает без предустановленных API ключей"
echo "   • Пользователи добавляют свои ключи в настройках"
echo "   • Вы монетизируете платформу, а не API ключи"
echo ""
echo "📝 Следующие шаги:"
echo "1. Откройте http://localhost:3000 в браузере"
echo "2. Зарегистрируйте нового пользователя"
echo "3. В настройках профиля добавьте API ключи от:"
echo "   - OpenAI (https://platform.openai.com/api-keys)"
echo "   - Anthropic (https://console.anthropic.com/settings/keys)"
echo "   - OpenRouter (https://openrouter.ai/keys)"
echo "4. Создайте первый проект"
echo ""
echo "🛑 Для остановки: docker-compose down"

# Сохранение PID для остановки
echo $API_PID > .api.pid
