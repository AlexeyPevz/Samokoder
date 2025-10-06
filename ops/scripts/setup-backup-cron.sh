#!/bin/bash
#
# Setup automatic backups via cron
# Использование: sudo ./setup-backup-cron.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SCRIPT="$SCRIPT_DIR/backup.sh"

echo "🔧 Setting up automatic PostgreSQL backups..."

# Проверка что скрипт существует
if [ ! -f "$BACKUP_SCRIPT" ]; then
    echo "❌ Error: backup.sh not found at $BACKUP_SCRIPT"
    exit 1
fi

# Создание crontab entry
CRON_JOB="0 */6 * * * $BACKUP_SCRIPT >> /var/log/samokoder-backup.log 2>&1"

# Проверка существующих cron jobs
if crontab -l 2>/dev/null | grep -q "$BACKUP_SCRIPT"; then
    echo "⚠️  Backup cron job already exists"
    echo "Current crontab:"
    crontab -l | grep "$BACKUP_SCRIPT"
else
    # Добавление cron job
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "✅ Backup cron job added:"
    echo "   Schedule: Every 6 hours (0 */6 * * *)"
    echo "   Script: $BACKUP_SCRIPT"
    echo "   Log: /var/log/samokoder-backup.log"
fi

# Создание директории для бэкапов
mkdir -p /var/backups/samokoder/postgres
chmod 750 /var/backups/samokoder/postgres

echo ""
echo "📋 Current crontab:"
crontab -l | grep -v "^#" | grep -v "^$"

echo ""
echo "🎉 Automatic backups configured!"
echo ""
echo "📝 Next steps:"
echo "   1. Set environment variables in /etc/environment or docker-compose.yml:"
echo "      - DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD"
echo "      - BACKUP_DIR (default: /var/backups/samokoder/postgres)"
echo "      - RETENTION_DAYS (default: 7)"
echo "   2. Test manually: $BACKUP_SCRIPT"
echo "   3. Monitor logs: tail -f /var/log/samokoder-backup.log"

exit 0
