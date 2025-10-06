#!/bin/bash
#
# PostgreSQL Backup Script для Samokoder
# Использование: ./backup.sh [local|s3]
#

set -e

# Конфигурация
BACKUP_DIR="${BACKUP_DIR:-/var/backups/samokoder/postgres}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-samokoder}"
DB_USER="${DB_USER:-user}"
DB_PASSWORD="${DB_PASSWORD:-password}"

# S3 configuration (опционально)
S3_BUCKET="${S3_BUCKET:-}"
S3_PREFIX="${S3_PREFIX:-backups/postgres}"

# Цвета для логов
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Создание директории для бэкапов
mkdir -p "$BACKUP_DIR"

# Генерация имени файла с timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/samokoder_${TIMESTAMP}.sql.gz"

log_info "Starting PostgreSQL backup..."
log_info "Database: ${DB_NAME}@${DB_HOST}:${DB_PORT}"
log_info "Backup file: $BACKUP_FILE"

# Экспорт пароля для pg_dump
export PGPASSWORD="$DB_PASSWORD"

# Создание бэкапа
if pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    --format=plain \
    --no-owner \
    --no-acl \
    --verbose 2>&1 | gzip > "$BACKUP_FILE"; then
    
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log_info "✅ Backup completed successfully"
    log_info "Backup size: $BACKUP_SIZE"
else
    log_error "❌ Backup failed!"
    exit 1
fi

# Очистка паролядля безопасности
unset PGPASSWORD

# Удаление старых бэкапов
log_info "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "samokoder_*.sql.gz" -type f -mtime +"$RETENTION_DAYS" -delete
REMAINING_BACKUPS=$(find "$BACKUP_DIR" -name "samokoder_*.sql.gz" -type f | wc -l)
log_info "Remaining backups: $REMAINING_BACKUPS"

# Загрузка в S3 (если настроено)
if [ -n "$S3_BUCKET" ] && [ "$1" = "s3" ]; then
    log_info "Uploading backup to S3: s3://${S3_BUCKET}/${S3_PREFIX}/"
    
    if command -v aws &> /dev/null; then
        if aws s3 cp "$BACKUP_FILE" "s3://${S3_BUCKET}/${S3_PREFIX}/$(basename $BACKUP_FILE)"; then
            log_info "✅ Backup uploaded to S3 successfully"
        else
            log_error "❌ S3 upload failed!"
        fi
    else
        log_warn "AWS CLI not found. Skipping S3 upload."
    fi
fi

# Статистика
log_info "==================================="
log_info "Backup Summary:"
log_info "  File: $(basename $BACKUP_FILE)"
log_info "  Size: $BACKUP_SIZE"
log_info "  Location: $BACKUP_DIR"
log_info "  Retention: $RETENTION_DAYS days"
log_info "  Total backups: $REMAINING_BACKUPS"
log_info "==================================="

exit 0
