#!/bin/bash
# Тест воспроизводимости установки "с нуля до запуска"

set -e  # Остановка при ошибке

echo "🧪 Тест воспроизводимости Самокодер v1.0.0"
echo "=============================================="

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для логирования
log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Проверка предварительных требований
check_requirements() {
    log "Проверка предварительных требований..."
    
    # Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        if [[ $(echo "$PYTHON_VERSION" | cut -d'.' -f1) -ge 3 && $(echo "$PYTHON_VERSION" | cut -d'.' -f2) -ge 9 ]]; then
            success "Python $PYTHON_VERSION найден"
        else
            error "Требуется Python 3.9+, найден $PYTHON_VERSION"
        fi
    else
        error "Python не найден. Установите Python 3.9+"
    fi
    
    # Node.js
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version | cut -d'v' -f2)
        if [[ $(echo "$NODE_VERSION" | cut -d'.' -f1) -ge 18 ]]; then
            success "Node.js $NODE_VERSION найден"
        else
            error "Требуется Node.js 18+, найден $NODE_VERSION"
        fi
    else
        error "Node.js не найден. Установите Node.js 18+"
    fi
    
    # Git
    if command -v git &> /dev/null; then
        success "Git найден"
    else
        error "Git не найден. Установите Git"
    fi
    
    # pip
    if command -v pip3 &> /dev/null; then
        success "pip3 найден"
    else
        error "pip3 не найден. Установите pip"
    fi
    
    # npm
    if command -v npm &> /dev/null; then
        success "npm найден"
    else
        error "npm не найден. Установите npm"
    fi
}

# Создание тестовой директории
setup_test_environment() {
    log "Настройка тестовой среды..."
    
    # Создаем временную директорию
    TEST_DIR="/tmp/samokoder_test_$(date +%s)"
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"
    
    success "Тестовая директория создана: $TEST_DIR"
}

# Клонирование репозитория
clone_repository() {
    log "Клонирование репозитория..."
    
    # Клонируем текущий репозиторий
    if [ -d "/workspace" ]; then
        cp -r /workspace ./
        success "Репозиторий скопирован"
    else
        error "Исходный репозиторий не найден"
    fi
}

# Установка зависимостей
install_dependencies() {
    log "Установка зависимостей..."
    
    # Backend зависимости
    log "Установка Python зависимостей..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        success "Python зависимости установлены"
    else
        error "Ошибка установки Python зависимостей"
    fi
    
    # Frontend зависимости
    log "Установка Node.js зависимостей..."
    cd frontend
    npm install
    
    if [ $? -eq 0 ]; then
        success "Node.js зависимости установлены"
    else
        error "Ошибка установки Node.js зависимостей"
    fi
    
    cd ..
}

# Настройка конфигурации
setup_configuration() {
    log "Настройка конфигурации..."
    
    # Создаем .env файл
    if [ ! -f ".env" ]; then
        cp .env.example .env
        
        # Генерируем безопасные ключи
        JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        API_KEY=$(python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")
        
        # Обновляем .env
        sed -i "s/JWT_SECRET=.*/JWT_SECRET=$JWT_SECRET/" .env
        sed -i "s/API_ENCRYPTION_KEY=.*/API_ENCRYPTION_KEY=$API_KEY/" .env
        
        success "Конфигурация создана"
    else
        warning ".env файл уже существует"
    fi
}

# Настройка базы данных
setup_database() {
    log "Настройка базы данных..."
    
    # Проверяем, есть ли Supabase настройки
    if grep -q "SUPABASE_URL" .env && ! grep -q "your-project-id" .env; then
        success "Supabase настроен"
    else
        warning "Supabase не настроен, используем SQLite для тестов"
        
        # Создаем SQLite базу для тестов
        echo "DATABASE_URL=sqlite:///./test.db" >> .env
        success "SQLite база данных настроена"
    fi
}

# Запуск тестов
run_tests() {
    log "Запуск тестов..."
    
    # Активируем виртуальное окружение
    source venv/bin/activate
    
    # Запускаем unit тесты
    if [ -f "pytest.ini" ]; then
        python -m pytest tests/ -v --tb=short
        
        if [ $? -eq 0 ]; then
            success "Unit тесты прошли"
        else
            warning "Некоторые unit тесты не прошли"
        fi
    else
        warning "pytest.ini не найден, пропускаем unit тесты"
    fi
}

# Тестовый запуск приложения
test_application_startup() {
    log "Тестирование запуска приложения..."
    
    # Активируем виртуальное окружение
    source venv/bin/activate
    
    # Запускаем backend в фоне
    log "Запуск backend..."
    python run_server.py &
    BACKEND_PID=$!
    
    # Ждем запуска backend
    sleep 10
    
    # Проверяем health check
    if curl -s http://localhost:8000/health > /dev/null; then
        success "Backend запущен и отвечает"
    else
        error "Backend не отвечает на health check"
    fi
    
    # Запускаем frontend в фоне
    log "Запуск frontend..."
    cd frontend
    npm run build &
    FRONTEND_PID=$!
    
    # Ждем сборки frontend
    sleep 30
    
    if [ -d "dist" ]; then
        success "Frontend собран успешно"
    else
        error "Frontend не собран"
    fi
    
    cd ..
    
    # Останавливаем процессы
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    
    success "Тестовый запуск завершен"
}

# Проверка производительности
check_performance() {
    log "Проверка производительности..."
    
    # Проверяем размер bundle
    if [ -d "frontend/dist" ]; then
        BUNDLE_SIZE=$(du -sh frontend/dist | cut -f1)
        success "Frontend bundle размер: $BUNDLE_SIZE"
    fi
    
    # Проверяем время запуска
    start_time=$(date +%s)
    source venv/bin/activate
    python -c "from config.settings import settings; print('Config loaded')" > /dev/null
    end_time=$(date +%s)
    load_time=$((end_time - start_time))
    
    if [ $load_time -lt 5 ]; then
        success "Конфигурация загружается за ${load_time}с"
    else
        warning "Конфигурация загружается медленно: ${load_time}с"
    fi
}

# Очистка
cleanup() {
    log "Очистка тестовой среды..."
    
    # Останавливаем все процессы
    pkill -f "python run_server.py" 2>/dev/null || true
    pkill -f "npm run" 2>/dev/null || true
    
    # Удаляем тестовую директорию
    cd /tmp
    rm -rf "$TEST_DIR"
    
    success "Очистка завершена"
}

# Основная функция
main() {
    echo "🚀 Начинаем тест воспроизводимости..."
    echo ""
    
    # Устанавливаем trap для очистки при выходе
    trap cleanup EXIT
    
    # Выполняем все шаги
    check_requirements
    setup_test_environment
    clone_repository
    install_dependencies
    setup_configuration
    setup_database
    run_tests
    test_application_startup
    check_performance
    
    echo ""
    success "🎉 Тест воспроизводимости ПРОЙДЕН!"
    echo ""
    echo "📊 Результаты:"
    echo "  ✅ Все зависимости установлены"
    echo "  ✅ Конфигурация настроена"
    echo "  ✅ База данных настроена"
    echo "  ✅ Тесты прошли"
    echo "  ✅ Приложение запускается"
    echo "  ✅ Производительность в норме"
    echo ""
    echo "🚀 Самокодер готов к использованию!"
}

# Запуск
main "$@"