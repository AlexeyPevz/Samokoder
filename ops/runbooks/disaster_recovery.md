# Disaster Recovery Runbook для Samokoder

**Дата создания:** 2025-10-01  
**Версия:** 1.0  
**Автор:** DevOps Team

---

## Обзор

Этот runbook описывает процедуры восстановления системы Samokoder при различных сценариях катастрофы.

**Целевые метрики:**
- **RPO (Recovery Point Objective):** < 6 часов
- **RTO (Recovery Time Objective):** < 2 часа

---

## Сценарий 1: Полная потеря PostgreSQL данных

### Симптомы
- База данных недоступна
- Ошибки подключения в логах API
- Health check падает

### Процедура восстановления

#### Шаг 1: Оценка ситуации (5 минут)
```bash
# Проверка состояния PostgreSQL
docker ps | grep postgres
docker logs samokoder-postgres

# Проверка доступности БД
psql -h localhost -p 5432 -U user -d samokoder -c "SELECT 1;"
```

#### Шаг 2: Поиск последнего бэкапа (5 минут)
```bash
# Локальные бэкапы
ls -lh /var/backups/samokoder/postgres/

# Выбор последнего бэкапа
LATEST_BACKUP=$(ls -t /var/backups/samokoder/postgres/samokoder_*.sql.gz | head -1)
echo "Latest backup: $LATEST_BACKUP"
```

#### Шаг 3: Остановка зависимых сервисов (2 минуты)
```bash
# Остановка API (предотвращаем новые запросы)
docker stop samokoder-api

# Уведомление пользователей (503 Service Unavailable)
# Traefik автоматически покажет 503
```

#### Шаг 4: Восстановление БД (30-60 минут)
```bash
# Запуск скрипта восстановления
cd /opt/samokoder/ops/scripts
sudo ./restore.sh $LATEST_BACKUP

# Мониторинг процесса восстановления
tail -f /var/log/samokoder-restore.log
```

#### Шаг 5: Проверка целостности (10 минут)
```bash
# Проверка подключения
psql -h localhost -p 5432 -U user -d samokoder -c "\dt"

# Подсчёт критичных таблиц
psql -h localhost -p 5432 -U user -d samokoder -c "
    SELECT 'users' as table, COUNT(*) FROM users
    UNION ALL
    SELECT 'projects', COUNT(*) FROM projects
    UNION ALL
    SELECT 'files', COUNT(*) FROM files;
"

# Проверка последней записи
psql -h localhost -p 5432 -U user -d samokoder -c "
    SELECT MAX(created_at) as last_record FROM projects;
"
```

#### Шаг 6: Запуск миграций (если нужно) (5 минут)
```bash
cd /opt/samokoder
docker exec samokoder-api alembic upgrade head
```

#### Шаг 7: Запуск сервисов (5 минут)
```bash
# Запуск API
docker start samokoder-api

# Проверка health check
curl http://localhost:8000/health
```

#### Шаг 8: Smoke testing (10 минут)
```bash
# Тест аутентификации
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'

# Тест списка проектов
curl http://localhost:8000/api/v1/projects \
  -H "Authorization: Bearer <token>"
```

#### Шаг 9: Мониторинг (30 минут)
```bash
# Мониторинг логов
docker logs -f samokoder-api | grep ERROR

# Проверка метрик
# (если Prometheus настроен)
curl http://localhost:9090/api/v1/query?query=up{job="samokoder-api"}
```

#### Шаг 10: Постмортем (после восстановления)
- Документировать что пошло не так
- Расчёт фактического downtime
- Обновление runbook при необходимости

---

## Сценарий 2: Corruption данных (без потери БД)

### Симптомы
- БД доступна, но данные повреждены
- Странное поведение приложения
- Constraint violations в логах

### Процедура восстановления

#### Шаг 1: Немедленный бэкап текущего состояния
```bash
# Сохраняем "плохое" состояние для анализа
cd /opt/samokoder/ops/scripts
./backup.sh
mv /var/backups/samokoder/postgres/samokoder_*.sql.gz \
   /var/backups/samokoder/postgres/corrupted_$(date +%Y%m%d_%H%M%S).sql.gz
```

#### Шаг 2: Partial restore (таблицы по отдельности)
```bash
# Восстановление конкретной таблицы
gunzip -c $LATEST_BACKUP | \
  grep -A 10000 "COPY projects" | \
  psql -h localhost -U user -d samokoder_temp

# Сравнение данных
# (вручную или через SQL diff)
```

---

## Сценарий 3: Полная потеря сервера

### Симптомы
- Сервер недоступен
- Timeout на все запросы

### Процедура восстановления

#### Шаг 1: Provision нового сервера (20-30 минут)
```bash
# Yandex Cloud CLI
yc compute instance create \
  --name samokoder-recovery \
  --zone ru-central1-a \
  --network-interface subnet-name=default,nat-ip-version=ipv4 \
  --create-boot-disk image-folder-id=standard-images,image-family=ubuntu-2204-lts,size=50 \
  --memory 8 \
  --cores 4
```

#### Шаг 2: Установка зависимостей (10 минут)
```bash
# Docker
curl -fsSL https://get.docker.com | sh

# Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### Шаг 3: Клонирование репозитория (5 минут)
```bash
git clone https://github.com/your-org/samokoder.git /opt/samokoder
cd /opt/samokoder
```

#### Шаг 4: Восстановление .env файла (5 минут)
```bash
# Из backup или secure storage (Vault, 1Password, etc.)
cat > .env << EOF
SECRET_KEY=<восстановленный ключ>
APP_SECRET_KEY=<восстановленный ключ>
DATABASE_URL=postgresql+asyncpg://user:password@pg:5432/samokoder
# ... остальные переменные
EOF
```

#### Шаг 5: Скачивание бэкапа из S3 (если настроено) (10 минут)
```bash
# Из S3
aws s3 cp s3://samokoder-backups/postgres/latest.sql.gz \
  /var/backups/samokoder/postgres/

# Или из другого сервера через scp
scp backup-server:/backups/samokoder/latest.sql.gz \
  /var/backups/samokoder/postgres/
```

#### Шаг 6: Запуск инфраструктуры (15 минут)
```bash
cd /opt/samokoder
docker-compose up -d pg redis

# Ждём готовности PostgreSQL
until docker exec samokoder-postgres pg_isready; do
  echo "Waiting for postgres..."
  sleep 2
done
```

#### Шаг 7: Восстановление данных (30-60 минут)
```bash
cd /opt/samokoder/ops/scripts
./restore.sh /var/backups/samokoder/postgres/latest.sql.gz
```

#### Шаг 8: Запуск приложения (10 минут)
```bash
cd /opt/samokoder
docker-compose up -d api frontend

# Проверка health
curl http://localhost:8000/health
```

#### Шаг 9: DNS failover (5 минут)
```bash
# Обновление DNS записи на новый IP
# (зависит от вашего DNS провайдера)
```

---

## Сценарий 4: Потеря Redis (сессии и кеш)

### Симптомы
- Rate limiting не работает
- Пользователи теряют сессии

### Процедура восстановления

#### Шаг 1: Перезапуск Redis (2 минуты)
```bash
docker restart samokoder-redis

# Проверка
docker exec samokoder-redis redis-cli ping
# Ответ: PONG
```

#### Шаг 2: Warm-up cache (опционально)
```bash
# Redis восстановится автоматически
# Кеш будет пересоздаваться по мере запросов
```

**Примечание:** Потеря Redis не критична для работы системы (данные не теряются, только кеш и rate limiting).

---

## Контакты для эскалации

| Роль | Контакт | Когда звонить |
|------|---------|---------------|
| DevOps Lead | @devops-lead | Если восстановление > 1 часа |
| CTO | @cto | Если downtime > 2 часа |
| Oncall Engineer | oncall@samokoder.com | 24/7 |

---

## Checklist до инцидента

- [ ] Бэкапы создаются автоматически (каждые 6 часов)
- [ ] Последний бэкап проверен и валиден
- [ ] Процедура restore протестирована на staging
- [ ] Все пароли и ключи сохранены в secure storage
- [ ] Мониторинг и алерты настроены
- [ ] Runbook актуален и доступен команде

---

## Checklist после инцидента

- [ ] Postmortem документ создан
- [ ] Root cause выявлен
- [ ] Превентивные меры добавлены в backlog
- [ ] Runbook обновлён на основе опыта
- [ ] Команда проинформирована об изменениях
