#!/bin/sh
# AlertManager entrypoint для подстановки environment variables

set -e

# Создаём рабочую конфигурацию из шаблона
CONFIG_TEMPLATE="/etc/alertmanager/alertmanager.yml"
CONFIG_FILE="/tmp/alertmanager.yml"

# Если переменные не установлены, используем пустые строки
export TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-""}
export TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-0}
export ALERT_EMAIL=${ALERT_EMAIL:-""}
export SMTP_HOST=${SMTP_HOST:-"smtp.gmail.com"}
export SMTP_PORT=${SMTP_PORT:-587}
export SMTP_USER=${SMTP_USER:-""}
export SMTP_PASS=${SMTP_PASS:-""}

# Проверяем наличие envsubst
if ! command -v envsubst >/dev/null 2>&1; then
    echo "Warning: envsubst not found, using config as-is"
    CONFIG_FILE="$CONFIG_TEMPLATE"
else
    # Подставляем переменные окружения
    envsubst < "$CONFIG_TEMPLATE" > "$CONFIG_FILE"
    echo "✅ AlertManager config generated with environment variables"
fi

# Запускаем AlertManager
exec /bin/alertmanager \
    --config.file="$CONFIG_FILE" \
    --storage.path=/alertmanager \
    "$@"
