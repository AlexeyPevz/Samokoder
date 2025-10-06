#!/bin/bash
#
# Automated Rollback Script для Samokoder
# Использование: ./rollback.sh [options]
#
# Примеры:
#   ./rollback.sh --service=api --to-version=v1.2.3
#   ./rollback.sh --full --auto
#   ./rollback.sh --service=api --restore-db --to-version=v1.2.2
#

set -e

# Цвета для логов
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Параметры по умолчанию
SERVICE=""
TO_VERSION=""
AUTO=false
FULL=false
RESTORE_DB=false
DRY_RUN=false
BACKUP_FIRST=true

# Функции логирования
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Функция для отображения помощи
show_help() {
    cat << EOF
Automated Rollback Script для Samokoder

Usage: $0 [OPTIONS]

Options:
    --service=SERVICE       Сервис для отката (api, worker, frontend, all)
    --to-version=VERSION    Версия для отката (например, v1.2.3)
    --auto                  Автоматически определить последнюю рабочую версию
    --full                  Полный откат (все сервисы)
    --restore-db            Восстановить БД из backup (ОПАСНО!)
    --dry-run              Показать что будет сделано без выполнения
    --no-backup            Не создавать backup перед откатом (НЕ РЕКОМЕНДУЕТСЯ)
    -h, --help             Показать эту справку

Examples:
    # Откатить API к конкретной версии
    $0 --service=api --to-version=v1.2.3

    # Автоматический откат к последней working версии
    $0 --service=api --auto

    # Полный rollback с восстановлением БД
    $0 --full --to-version=v1.2.3 --restore-db

    # Dry-run перед выполнением
    $0 --service=api --to-version=v1.2.3 --dry-run

EOF
    exit 0
}

# Парсинг аргументов
for arg in "$@"; do
    case $arg in
        --service=*)
            SERVICE="${arg#*=}"
            ;;
        --to-version=*)
            TO_VERSION="${arg#*=}"
            ;;
        --auto)
            AUTO=true
            ;;
        --full)
            FULL=true
            ;;
        --restore-db)
            RESTORE_DB=true
            ;;
        --dry-run)
            DRY_RUN=true
            ;;
        --no-backup)
            BACKUP_FIRST=false
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log_error "Unknown option: $arg"
            show_help
            ;;
    esac
done

# Валидация параметров
if [ "$FULL" = false ] && [ -z "$SERVICE" ]; then
    log_error "Необходимо указать --service или --full"
    show_help
fi

if [ "$AUTO" = false ] && [ -z "$TO_VERSION" ]; then
    log_error "Необходимо указать --to-version или --auto"
    show_help
fi

# Функция для получения текущей версии
get_current_version() {
    local service=$1
    docker ps --filter "name=samokoder-${service}" --format "{{.Image}}" | cut -d':' -f2
}

# Функция для автоопределения последней рабочей версии
auto_detect_version() {
    log_info "Автоматическое определение последней рабочей версии..."
    
    # Получить последние 5 tags
    local tags=$(git tag -l --sort=-v:refname | head -5)
    
    # Текущая версия
    local current_version=$(get_current_version "api")
    
    # Найти предыдущую версию
    local previous_version=""
    local found_current=false
    
    for tag in $tags; do
        if [ "$tag" = "$current_version" ]; then
            found_current=true
            continue
        fi
        
        if [ "$found_current" = true ]; then
            previous_version=$tag
            break
        fi
    done
    
    if [ -z "$previous_version" ]; then
        log_error "Не удалось автоматически определить предыдущую версию"
        exit 1
    fi
    
    log_info "Определена предыдущая версия: $previous_version"
    echo "$previous_version"
}

# Функция для создания backup
create_backup() {
    if [ "$BACKUP_FIRST" = false ]; then
        log_warn "Пропуск создания backup (--no-backup)"
        return 0
    fi
    
    log_step "Создание backup перед откатом..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would create backup"
        return 0
    fi
    
    local backup_script="$(dirname $0)/backup.sh"
    if [ -f "$backup_script" ]; then
        $backup_script
    else
        log_warn "Backup скрипт не найден: $backup_script"
        read -p "Продолжить без backup? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            log_error "Откат отменен"
            exit 1
        fi
    fi
}

# Функция для отката сервиса
rollback_service() {
    local service=$1
    local version=$2
    
    log_step "Откат сервиса: $service к версии: $version"
    
    # Получить текущую версию
    local current_version=$(get_current_version "$service")
    log_info "Текущая версия $service: $current_version"
    
    if [ "$current_version" = "$version" ]; then
        log_warn "Сервис $service уже на версии $version"
        return 0
    fi
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would rollback $service: $current_version -> $version"
        return 0
    fi
    
    # Установить версию в environment
    export APP_VERSION=$version
    
    # Pull образ
    log_info "Pulling image for $service version $version..."
    docker-compose pull $service
    
    # Остановить текущий контейнер
    log_info "Stopping current $service container..."
    docker-compose stop $service
    
    # Запустить новый контейнер
    log_info "Starting $service with version $version..."
    docker-compose up -d --no-deps $service
    
    # Проверить статус
    sleep 5
    if docker ps --filter "name=samokoder-${service}" --filter "status=running" | grep -q "samokoder-${service}"; then
        log_info "✅ Сервис $service успешно откачен к версии $version"
    else
        log_error "❌ Не удалось запустить сервис $service"
        exit 1
    fi
}

# Функция для проверки health
check_health() {
    log_step "Проверка health check..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would check health"
        return 0
    fi
    
    local max_attempts=12
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log_info "Health check попытка $attempt/$max_attempts..."
        
        if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            log_info "✅ Health check passed"
            return 0
        fi
        
        sleep 5
        attempt=$((attempt + 1))
    done
    
    log_error "❌ Health check failed after $max_attempts attempts"
    return 1
}

# Функция для восстановления БД
restore_database() {
    log_step "Восстановление базы данных..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would restore database"
        return 0
    fi
    
    log_warn "⚠️  ВНИМАНИЕ: Восстановление БД приведет к потере текущих данных!"
    read -p "Вы уверены? Введите 'yes' для подтверждения: " confirm
    
    if [ "$confirm" != "yes" ]; then
        log_error "Восстановление БД отменено"
        exit 1
    fi
    
    # Остановить зависимые сервисы
    log_info "Остановка API и Worker..."
    docker-compose stop api worker
    
    # Найти последний backup
    local backup_dir="/var/backups/samokoder/postgres"
    local latest_backup=$(ls -t $backup_dir/samokoder_*.sql.gz 2>/dev/null | head -1)
    
    if [ -z "$latest_backup" ]; then
        log_error "Backup файлы не найдены в $backup_dir"
        exit 1
    fi
    
    log_info "Используется backup: $latest_backup"
    
    # Запустить restore скрипт
    local restore_script="$(dirname $0)/restore.sh"
    if [ -f "$restore_script" ]; then
        $restore_script "$latest_backup"
    else
        log_error "Restore скрипт не найден: $restore_script"
        exit 1
    fi
    
    log_info "✅ База данных восстановлена"
}

# Функция для запуска smoke tests
run_smoke_tests() {
    log_step "Запуск smoke tests..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would run smoke tests"
        return 0
    fi
    
    local smoke_test_script="$(dirname $0)/smoke-test.sh"
    
    if [ -f "$smoke_test_script" ]; then
        if $smoke_test_script; then
            log_info "✅ Smoke tests passed"
        else
            log_error "❌ Smoke tests failed"
            return 1
        fi
    else
        log_warn "Smoke test скрипт не найден: $smoke_test_script"
    fi
}

# Главная функция
main() {
    echo "========================================"
    echo "  Samokoder Rollback Script"
    echo "========================================"
    echo ""
    
    # Определение версии для отката
    if [ "$AUTO" = true ]; then
        TO_VERSION=$(auto_detect_version)
    fi
    
    log_info "Параметры отката:"
    log_info "  Service: ${SERVICE:-all}"
    log_info "  Target version: $TO_VERSION"
    log_info "  Restore DB: $RESTORE_DB"
    log_info "  Dry run: $DRY_RUN"
    echo ""
    
    # Подтверждение
    if [ "$DRY_RUN" = false ]; then
        read -p "Начать откат? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            log_error "Откат отменен пользователем"
            exit 0
        fi
    fi
    
    # Создать backup
    create_backup
    
    # Восстановить БД (если указано)
    if [ "$RESTORE_DB" = true ]; then
        restore_database
    fi
    
    # Откат сервисов
    if [ "$FULL" = true ]; then
        rollback_service "api" "$TO_VERSION"
        rollback_service "worker" "$TO_VERSION"
        rollback_service "frontend" "$TO_VERSION"
    else
        rollback_service "$SERVICE" "$TO_VERSION"
    fi
    
    # Проверка health
    if ! check_health; then
        log_error "Health check failed после отката"
        log_error "Система может быть в нестабильном состоянии"
        exit 1
    fi
    
    # Smoke tests
    run_smoke_tests
    
    echo ""
    echo "========================================"
    log_info "✅ Откат завершен успешно!"
    echo "========================================"
    echo ""
    log_info "Следующие шаги:"
    log_info "  1. Проверить метрики в Grafana"
    log_info "  2. Мониторить логи: docker-compose logs -f api"
    log_info "  3. Проверить алерты в AlertManager"
    log_info "  4. Создать incident report"
    log_info "  5. Запланировать post-mortem"
    echo ""
}

# Запуск
main
