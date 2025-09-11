#!/bin/bash

# Скрипт для запуска разработки фронтенда и бэкенда

echo "🚀 Запуск среды разработки..."

# Функция для очистки процессов при выходе
cleanup() {
    echo "🛑 Остановка серверов..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

# Устанавливаем обработчик сигналов
trap cleanup SIGINT SIGTERM

# Запускаем бэкенд
echo "🔧 Запуск бэкенда на порту 8000..."
cd /workspace
python run_server.py &
BACKEND_PID=$!

# Ждем немного, чтобы бэкенд запустился
sleep 3

# Запускаем фронтенд
echo "🎨 Запуск фронтенда на порту 5173..."
cd /workspace/frontend
npm run dev &
FRONTEND_PID=$!

echo "✅ Серверы запущены!"
echo "📱 Фронтенд: http://localhost:5173"
echo "🔧 Бэкенд: http://localhost:8000"
echo "📚 Документация API: http://localhost:8000/docs"
echo ""
echo "Нажмите Ctrl+C для остановки всех серверов"

# Ждем завершения
wait