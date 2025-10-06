#!/bin/bash
#
# PostgreSQL Restore Script для Samokoder
# Использование: ./restore.sh <backup_file.sql.gz>
#

set -e

# Конфигурация
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-samokoder}"
DB_USER="${DB_USER:-user}"
DB_PASSWORD="${DB_PASSWORD:-password}"

# Цвета для логов
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Проверка аргументов
if [ $# -eq 0 ]; then
    log_error "Usage: $0 <backup_file.sql.gz>"
    log_info "Available backups:"
    find /var/backups/samokoder/postgres -name "samokoder_*.sql.gz" -type f -exec ls -lh {} \; 2>/dev/null || echo "  No backups found"
    exit 1
fi

BACKUP_FILE="$1"

# Проверка существования файла
if [ ! -f "$BACKUP_FILE" ]; then
    log_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

log_warn "⚠️  WARNING: This will DROP and RECREATE the database '$DB_NAME'"
log_warn "⚠️  All current data will be LOST!"
read -p "Are you sure you want to continue? (yes/no): " -r
echo
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    log_info "Restore cancelled"
    exit 0
fi

log_info "Starting PostgreSQL restore..."
log_info "Database: ${DB_NAME}@${DB_HOST}:${DB_PORT}"
log_info "Backup file: $BACKUP_FILE"

# Экспорт пароля для psql
export PGPASSWORD="$DB_PASSWORD"

# Останавливаем все соединения к БД
log_info "Terminating active connections..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$DB_NAME' AND pid <> pg_backend_pid();" \
    2>/dev/null || log_warn "Could not terminate connections (database might not exist yet)"

# Удаление старой БД и создание новой
log_info "Dropping database '$DB_NAME'..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;" || {
    log_error "Failed to drop database"
    exit 1
}

log_info "Creating database '$DB_NAME'..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME;" || {
    log_error "Failed to create database"
    exit 1
}

# Восстановление из бэкапа
log_info "Restoring from backup..."
if gunzip -c "$BACKUP_FILE" | psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" --quiet; then
    log_info "✅ Restore completed successfully"
else
    log_error "❌ Restore failed!"
    exit 1
fi

# Очистка пароля
unset PGPASSWORD

# Статистика
DB_SIZE=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -t -c \
    "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" | xargs)

log_info "==================================="
log_info "Restore Summary:"
log_info "  Database: $DB_NAME"
log_info "  Size: $DB_SIZE"
log_info "  Backup: $(basename $BACKUP_FILE)"
log_info "==================================="

log_info "🎉 Database restored successfully!"

exit 0
