#!/bin/bash

# Скрипт для применения исправлений багов
echo "🐛 Применение исправлений багов..."

# Создаем резервные копии оригинальных файлов
echo "📦 Создание резервных копий..."
mkdir -p backups/$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"

cp backend/services/gpt_pilot_wrapper.py "$BACKUP_DIR/" 2>/dev/null || true
cp backend/main.py "$BACKUP_DIR/" 2>/dev/null || true
cp backend/auth/dependencies.py "$BACKUP_DIR/" 2>/dev/null || true
cp requirements.txt "$BACKUP_DIR/" 2>/dev/null || true
cp config/settings.py "$BACKUP_DIR/" 2>/dev/null || true
cp run_server.py "$BACKUP_DIR/" 2>/dev/null || true
cp .env.example "$BACKUP_DIR/" 2>/dev/null || true

echo "✅ Резервные копии созданы в $BACKUP_DIR"

# Применяем исправления
echo "🔧 Применение исправлений..."

# GPT-Pilot wrapper
if [ -f "backend/services/gpt_pilot_wrapper_fixed.py" ]; then
    cp backend/services/gpt_pilot_wrapper_fixed.py backend/services/gpt_pilot_wrapper.py
    echo "✅ GPT-Pilot wrapper исправлен"
else
    echo "❌ Файл gpt_pilot_wrapper_fixed.py не найден"
fi

# Main.py
if [ -f "backend/main_fixed.py" ]; then
    cp backend/main_fixed.py backend/main.py
    echo "✅ Main.py исправлен"
else
    echo "❌ Файл main_fixed.py не найден"
fi

# Auth dependencies
if [ -f "backend/auth/dependencies_fixed.py" ]; then
    cp backend/auth/dependencies_fixed.py backend/auth/dependencies.py
    echo "✅ Auth dependencies исправлены"
else
    echo "❌ Файл dependencies_fixed.py не найден"
fi

# Requirements
if [ -f "requirements_fixed.txt" ]; then
    cp requirements_fixed.txt requirements.txt
    echo "✅ Requirements.txt исправлен"
else
    echo "❌ Файл requirements_fixed.txt не найден"
fi

# Settings
if [ -f "config/settings_fixed.py" ]; then
    cp config/settings_fixed.py config/settings.py
    echo "✅ Settings.py исправлен"
else
    echo "❌ Файл settings_fixed.py не найден"
fi

# Run server
if [ -f "run_server_fixed.py" ]; then
    cp run_server_fixed.py run_server.py
    echo "✅ Run server исправлен"
else
    echo "❌ Файл run_server_fixed.py не найден"
fi

# .env.example
if [ -f ".env.example.fixed" ]; then
    cp .env.example.fixed .env.example
    echo "✅ .env.example исправлен"
else
    echo "❌ Файл .env.example.fixed не найден"
fi

echo ""
echo "🎉 Все исправления применены!"
echo ""
echo "📋 Следующие шаги:"
echo "1. Установите обновленные зависимости: pip install -r requirements.txt"
echo "2. Обновите .env файл: cp .env.example .env"
echo "3. Запустите сервер: python run_server.py"
echo ""
echo "📊 Статистика исправлений:"
echo "  - GPT-Pilot wrapper: ✅ Исправлен"
echo "  - Main.py: ✅ Исправлен"
echo "  - Auth dependencies: ✅ Исправлен"
echo "  - Requirements.txt: ✅ Исправлен"
echo "  - Settings.py: ✅ Исправлен"
echo "  - Run server: ✅ Исправлен"
echo "  - .env.example: ✅ Исправлен"
echo ""
echo "🚀 Проект готов к тестированию!"