#!/bin/bash

# Скрипт для развертывания приложения Samokoder в Yandex Cloud
#
# Перед использованием:
# 1. Установите и настройте Yandex Cloud CLI (yc).
# 2. Убедитесь, что у вас есть права на пуш в Yandex Container Registry.
# 3. Создайте файл .env.prod с production-переменными.

set -e # Прерывать выполнение при любой ошибке

# --- Параметры (можно вынести в переменные окружения или передавать аргументами) ---
YC_REGISTRY_ID="cr.p..."
YC_DOCKER_REGISTRY="cr.yandex/${YC_REGISTRY_ID}"
APP_VERSION="latest"

# Имена образов
API_IMAGE_NAME="samokoder-api"
WORKER_IMAGE_NAME="samokoder-worker"
FRONTEND_IMAGE_NAME="samokoder-frontend"

# Параметры для подключения к серверу
# Пример: "user@123.45.67.89"
REMOTE_SERVER=""

# --- Функции ---

# Функция для вывода сообщений
log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Проверка параметров
if [ -z "${YC_REGISTRY_ID}" ] || [ -z "${REMOTE_SERVER}" ]; then
  log "❌ Ошибка: Переменные YC_REGISTRY_ID и REMOTE_SERVER должны быть установлены."
  exit 1
fi

# --- Шаг 1: Аутентификация в Yandex Container Registry ---
log "🔑 Аутентификация в Yandex Container Registry..."
yc container registry configure-docker
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

SSH_COMMANDS=""
SSH_COMMANDS+="cd ~/samokoder && " # Переходим в папку проекта на сервере
SSH_COMMANDS+="export YC_DOCKER_REGISTRY=${YC_DOCKER_REGISTRY} && "
SSH_COMMANDS+="export API_IMAGE_NAME=${API_IMAGE_NAME} && "
SSH_COMMANDS+="export WORKER_IMAGE_NAME=${WORKER_IMAGE_NAME} && "
SSH_COMMANDS+="export FRONTEND_IMAGE_NAME=${FRONTEND_IMAGE_NAME} && "
SSH_COMMANDS+="export APP_VERSION=${APP_VERSION} && "
SSH_COMMANDS+="docker-compose pull && " # Загружаем новые версии образов
SSH_COMMANDS+="docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --remove-orphans" # Перезапускаем сервисы

ssh -T ${REMOTE_SERVER} <<EOF
  ${SSH_COMMANDS}
EOF

log "🎉 Развертывание успешно завершено!"
