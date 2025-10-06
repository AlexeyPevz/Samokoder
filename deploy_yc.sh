#!/bin/bash

# Скрипт для развертывания приложения Samokoder в Yandex Cloud
#
# Перед использованием:
# 1. Установите и настройте Yandex Cloud CLI (yc).
# 2. Убедитесь, что у вас есть права на пуш в Yandex Container Registry.
# 3. Создайте файл .env.prod с production-переменными.
# 4. Установите переменные окружения YC_REGISTRY_ID и REMOTE_SERVER

set -euo pipefail  # Exit on error, undefined variable, pipe failure

# --- Параметры (можно вынести в переменные окружения или передавать аргументами) ---
YC_REGISTRY_ID="${YC_REGISTRY_ID:-}"
YC_DOCKER_REGISTRY="cr.yandex/${YC_REGISTRY_ID}"
APP_VERSION="${APP_VERSION:-latest}"

# Имена образов
API_IMAGE_NAME="samokoder-api"
WORKER_IMAGE_NAME="samokoder-worker"
FRONTEND_IMAGE_NAME="samokoder-frontend"

# Параметры для подключения к серверу
# Пример: "user@123.45.67.89"
REMOTE_SERVER="${REMOTE_SERVER:-}"

# --- Функции ---

# Функция для вывода сообщений
log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Проверка параметров
if [ -z "${YC_REGISTRY_ID}" ]; then
  log "❌ Ошибка: Переменная YC_REGISTRY_ID не установлена."
  log "Пример: export YC_REGISTRY_ID=crp1234567890abcdef"
  exit 1
fi

if [ -z "${REMOTE_SERVER}" ]; then
  log "❌ Ошибка: Переменная REMOTE_SERVER не установлена."
  log "Пример: export REMOTE_SERVER=user@123.45.67.89"
  exit 1
fi

# Проверка формата YC_REGISTRY_ID
if [[ ! "$YC_REGISTRY_ID" =~ ^crp[a-z0-9]+$ ]]; then
  log "❌ Ошибка: YC_REGISTRY_ID имеет неверный формат. Должен начинаться с 'crp'"
  log "Получите корректный ID командой: yc container registry list"
  exit 1
fi

# Проверка наличия .env.prod
if [ ! -f .env.prod ]; then
  log "⚠️  Файл .env.prod не найден. Создайте его из .env.example"
  log "Продолжить без .env.prod? (y/N)"
  read -r response
  if [[ ! "$response" =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# --- Шаг 1: Аутентификация в Yandex Container Registry ---
log "🔑 Аутентификация в Yandex Container Registry..."
if ! command -v yc &> /dev/null; then
  log "❌ Yandex Cloud CLI (yc) не установлен"
  log "Установите: https://cloud.yandex.ru/docs/cli/quickstart"
  exit 1
fi

yc container registry configure-docker || {
  log "❌ Ошибка аутентификации. Проверьте: yc config list"
  exit 1
}
log "✅ Аутентификация прошла успешно."

# --- Шаг 2: Сборка и Push Docker-образов ---
log "🔨 Сборка и отправка Docker-образов..."

# API
log "Сборка образа ${API_IMAGE_NAME}..."
docker build -t "${YC_DOCKER_REGISTRY}/${API_IMAGE_NAME}:${APP_VERSION}" -f Dockerfile .
log "Отправка образа ${API_IMAGE_NAME}..."
docker push "${YC_DOCKER_REGISTRY}/${API_IMAGE_NAME}:${APP_VERSION}"

# Worker
log "Сборка образа ${WORKER_IMAGE_NAME}..."
docker build -t "${YC_DOCKER_REGISTRY}/${WORKER_IMAGE_NAME}:${APP_VERSION}" -f Dockerfile . # Используем тот же Dockerfile
log "Отправка образа ${WORKER_IMAGE_NAME}..."
docker push "${YC_DOCKER_REGISTRY}/${WORKER_IMAGE_NAME}:${APP_VERSION}"

# Frontend
log "Сборка образа ${FRONTEND_IMAGE_NAME}..."
docker build -t "${YC_DOCKER_REGISTRY}/${FRONTEND_IMAGE_NAME}:${APP_VERSION}" -f frontend/Dockerfile ./frontend
log "Отправка образа ${FRONTEND_IMAGE_NAME}..."
docker push "${YC_DOCKER_REGISTRY}/${FRONTEND_IMAGE_NAME}:${APP_VERSION}"

log "✅ Все образы собраны и отправлены в Yandex Container Registry."

# --- Шаг 3: Развертывание на удаленном сервере ---
log "🚀 Развертывание на сервере ${REMOTE_SERVER}..."

# Проверка доступности сервера
if ! ssh -o ConnectTimeout=10 -o BatchMode=yes ${REMOTE_SERVER} exit 2>/dev/null; then
  log "❌ Не удается подключиться к ${REMOTE_SERVER}"
  log "Проверьте SSH ключи и доступность сервера"
  exit 1
fi

SSH_COMMANDS=""
SSH_COMMANDS+="set -euo pipefail && "
SSH_COMMANDS+="cd ~/samokoder && " # Переходим в папку проекта на сервере
SSH_COMMANDS+="export YC_DOCKER_REGISTRY=${YC_DOCKER_REGISTRY} && "
SSH_COMMANDS+="export API_IMAGE_NAME=${API_IMAGE_NAME} && "
SSH_COMMANDS+="export WORKER_IMAGE_NAME=${WORKER_IMAGE_NAME} && "
SSH_COMMANDS+="export FRONTEND_IMAGE_NAME=${FRONTEND_IMAGE_NAME} && "
SSH_COMMANDS+="export APP_VERSION=${APP_VERSION} && "
SSH_COMMANDS+="docker compose pull || docker-compose pull && " # Загружаем новые версии образов
SSH_COMMANDS+="docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --remove-orphans || docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --remove-orphans" # Перезапускаем сервисы

ssh -T ${REMOTE_SERVER} <<EOF || {
  log "❌ Ошибка при развертывании на сервере"
  exit 1
}
  ${SSH_COMMANDS}
EOF

log "✅ Проверка статуса сервисов..."
ssh -T ${REMOTE_SERVER} "cd ~/samokoder && (docker compose ps || docker-compose ps)" || true

log "🎉 Развертывание успешно завершено!"
log ""
log "📋 Полезные команды для управления на сервере:"
log "   Просмотр логов: ssh ${REMOTE_SERVER} 'cd ~/samokoder && docker compose logs -f'"
log "   Статус: ssh ${REMOTE_SERVER} 'cd ~/samokoder && docker compose ps'"
log "   Рестарт: ssh ${REMOTE_SERVER} 'cd ~/samokoder && docker compose restart'"
