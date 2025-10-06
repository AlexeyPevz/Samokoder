# Runbook: Операции с Мониторингом

## Обзор

Этот runbook описывает стандартные операции с системой мониторинга Samokoder.

---

## 1. Первый запуск мониторинга

### Предусловия
- Docker и docker-compose установлены
- `.env` настроен с Telegram/Email credentials

### Шаги

```bash
# 1. Создать .env из примера
cp .env.example .env

# 2. Настроить алерты (обязательно!)
nano .env
# Заполнить:
# - TELEGRAM_BOT_TOKEN
# - TELEGRAM_CHAT_ID
# - GRAFANA_ADMIN_PASSWORD (изменить с дефолтного!)

# 3. Запустить стек
docker-compose up -d

# 4. Проверить статус всех сервисов
docker-compose ps

# Ожидаемый результат: все сервисы "Up"
# - samokoder-api
# - samokoder-prometheus
# - samokoder-grafana
# - samokoder-alertmanager
# - samokoder-postgres-exporter
# - samokoder-redis-exporter
# - samokoder-cadvisor

# 5. Проверить метрики API
curl http://localhost:8000/metrics

# 6. Проверить Prometheus targets
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'

# 7. Войти в Grafana
# Открыть: http://localhost:3000
# Логин: admin / <ваш пароль из .env>

# 8. Проверить дашборд
# Grafana → Dashboards → Samokoder Overview

# 9. Тест алерта
curl -H "Content-Type: application/json" -d '[{"labels":{"alertname":"TestAlert","severity":"info"}}]' http://localhost:9093/api/v1/alerts

# Проверить Telegram - должно прийти сообщение
```

### Rollback

```bash
# Остановить мониторинг
docker-compose stop prometheus grafana alertmanager

# Полностью удалить (с данными!)
docker-compose down -v
```

---

## 2. Проверка здоровья мониторинга

### Симптомы
- Алерты не приходят
- Дашборды пустые
- Метрики отсутствуют

### Диагностика

```bash
# 1. Проверить статус контейнеров
docker-compose ps

# 2. Проверить логи
docker logs samokoder-prometheus --tail 100
docker logs samokoder-grafana --tail 100
docker logs samokoder-alertmanager --tail 100

# 3. Проверить Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health != "up")'

# Если targets down:
# - Проверить сетевое подключение: docker network inspect samokoder_samokoder
# - Проверить логи проблемного сервиса

# 4. Проверить конфигурацию Prometheus
docker exec samokoder-prometheus promtool check config /etc/prometheus/prometheus.yml

# 5. Проверить правила алертов
docker exec samokoder-prometheus promtool check rules /etc/prometheus/rules/alerts.yml

# 6. Проверить AlertManager конфигурацию
docker exec samokoder-alertmanager amtool check-config /etc/alertmanager/alertmanager.yml

# 7. Проверить datasource в Grafana
curl -s -u admin:<password> http://localhost:3000/api/datasources | jq '.[] | {name, type, url}'
```

### Исправление

```bash
# Перезапустить проблемный сервис
docker-compose restart prometheus

# Если нужно обновить конфигурацию:
# 1. Отредактировать файл
nano monitoring/prometheus/prometheus.yml

# 2. Проверить синтаксис
docker exec samokoder-prometheus promtool check config /etc/prometheus/prometheus.yml

# 3. Reload (без перезапуска)
curl -X POST http://localhost:9090/-/reload

# Для AlertManager:
curl -X POST http://localhost:9093/-/reload
```

---

## 3. Активный алерт: Расследование

### Пример: APIDown

**Notification**:
```
🚨 CRITICAL ALERT 🚨
Alert: APIDown
Component: api
Status: firing
Summary: Samokoder API is down
Description: The Samokoder API has been down for more than 1 minute.
Started: 2025-10-01T10:30:00Z
```

### Шаги расследования

```bash
# 1. Подтвердить проблему
curl http://localhost:8000/health
# Если таймаут или ошибка → API действительно down

# 2. Проверить статус контейнера
docker ps -a | grep samokoder-api

# Если контейнер stopped:
docker logs samokoder-api --tail 200

# Если контейнер restarting:
docker logs samokoder-api --tail 200 --follow

# 3. Проверить ресурсы
docker stats samokoder-api --no-stream

# 4. Проверить сеть
docker network inspect samokoder_samokoder | jq '.[] | .Containers'

# 5. Проверить зависимости (DB, Redis)
docker exec samokoder-db pg_isready -U samokoder
docker exec samokoder-redis redis-cli ping
```

### Mitigation

```bash
# Вариант 1: Перезапуск
docker-compose restart api

# Вариант 2: Пересборка (если код изменился)
docker-compose up -d --build api

# Вариант 3: Откат (если новый деплой сломал)
git checkout <previous-commit>
docker-compose up -d --build api

# После восстановления:
# - Проверить метрики: http://localhost:8000/metrics
# - Проверить дашборд: API Health gauge = 1
# - Алерт автоматически resolve через 5 минут
```

---

## 4. Добавление нового алерта

### Пример: Высокий расход LLM токенов

```bash
# 1. Отредактировать rules
nano monitoring/prometheus/rules/alerts.yml

# Добавить:
# - alert: HighLLMCost
#   expr: rate(samokoder_llm_tokens_consumed_total[1h]) > 500000
#   for: 15m
#   labels:
#     severity: warning
#     component: llm
#   annotations:
#     summary: "High LLM cost"
#     description: "Token consumption: {{ $value }} tokens/s"

# 2. Проверить синтаксис
docker exec samokoder-prometheus promtool check rules monitoring/prometheus/rules/alerts.yml

# 3. Reload Prometheus
curl -X POST http://localhost:9090/-/reload

# 4. Проверить в UI
# http://localhost:9090/alerts
# Найти новый алерт

# 5. Тест (опционально)
# Создать условие срабатывания или использовать:
curl -H "Content-Type: application/json" -d '[{"labels":{"alertname":"HighLLMCost","severity":"warning"}}]' http://localhost:9093/api/v1/alerts
```

---

## 5. Масштабирование хранилища Prometheus

### Симптомы
- Диск заполняется
- Prometheus OOM killed
- Медленные запросы

### Проверка

```bash
# 1. Размер данных
du -sh /var/lib/docker/volumes/samokoder_prometheus_data

# 2. Использование памяти
docker stats samokoder-prometheus --no-stream

# 3. Количество series
curl -s http://localhost:9090/api/v1/status/tsdb | jq '.data.numSeries'
```

### Решения

**Вариант 1: Увеличить retention (уменьшить)**

```yaml
# docker-compose.yml
prometheus:
  command:
    - '--storage.tsdb.retention.time=15d'  # Было 30d
```

**Вариант 2: Увеличить ресурсы**

```yaml
prometheus:
  deploy:
    resources:
      limits:
        memory: 4G  # Было 2G
      reservations:
        memory: 2G
```

**Вариант 3: Уменьшить scrape interval**

```yaml
# monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 30s  # Было 15s
```

**Вариант 4: Экспорт старых данных**

```bash
# Установить promtool
# Экспорт в файл
promtool tsdb dump /prometheus/data --output=/backup/prometheus-dump.json

# Или использовать remote_write в Thanos/Cortex
```

---

## 6. Обновление дашбордов Grafana

### Через UI

```bash
# 1. Grafana → Dashboards → Samokoder Overview
# 2. Edit panel
# 3. Save dashboard
# 4. Экспорт:
#    Share → Export → Save to file
# 5. Сохранить в репозиторий:
mv ~/Downloads/samokoder-overview.json monitoring/grafana/dashboards/

# 6. Commit
git add monitoring/grafana/dashboards/samokoder-overview.json
git commit -m "Update Grafana dashboard"
```

### Программно

```bash
# Создать dashboard.json
cat > monitoring/grafana/dashboards/new-dashboard.json << 'EOF'
{
  "title": "New Dashboard",
  ...
}
EOF

# Перезапустить Grafana для auto-provisioning
docker-compose restart grafana

# Проверить через 10 секунд (updateIntervalSeconds=10)
```

---

## 7. Backup метрик

### Prometheus snapshot

```bash
# 1. Создать snapshot
curl -X POST http://localhost:9090/api/v1/admin/tsdb/snapshot

# Response: {"status":"success","data":{"name":"20251001T103000Z-abc123"}}

# 2. Найти snapshot
docker exec samokoder-prometheus ls -lh /prometheus/snapshots/

# 3. Копировать наружу
docker cp samokoder-prometheus:/prometheus/snapshots/20251001T103000Z-abc123 ./backups/

# 4. Сжать
tar -czf prometheus-snapshot-20251001.tar.gz backups/20251001T103000Z-abc123
```

### Restore

```bash
# 1. Остановить Prometheus
docker-compose stop prometheus

# 2. Распаковать snapshot
tar -xzf prometheus-snapshot-20251001.tar.gz -C /tmp/

# 3. Копировать в volume
docker run --rm -v samokoder_prometheus_data:/data -v /tmp/20251001T103000Z-abc123:/backup alpine sh -c "rm -rf /data/* && cp -r /backup/* /data/"

# 4. Запустить Prometheus
docker-compose start prometheus
```

---

## 8. Замолчание алертов (Silencing)

### Планируемое обслуживание

```bash
# Silence на 2 часа
curl -X POST http://localhost:9093/api/v2/silences \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [
      {"name": "alertname", "value": ".*", "isRegex": true}
    ],
    "startsAt": "2025-10-01T20:00:00Z",
    "endsAt": "2025-10-01T22:00:00Z",
    "createdBy": "ops-team",
    "comment": "Scheduled maintenance: database migration"
  }'

# Проверить активные silences
curl http://localhost:9093/api/v2/silences | jq '.[] | {id, comment, endsAt}'

# Удалить silence
SILENCE_ID=<id>
curl -X DELETE http://localhost:9093/api/v2/silence/$SILENCE_ID
```

---

## Контакты эскалации

| Severity | Contact | Response Time |
|----------|---------|---------------|
| Critical | ops-oncall@samokoder.com | 15 min |
| Warning | ops-team@samokoder.com | 2 hours |
| Info | slack #ops-alerts | Best effort |

**Oncall rotation**: https://samokoder.pagerduty.com

---

## Чеклист для Production

- [ ] GRAFANA_ADMIN_PASSWORD изменен с дефолтного
- [ ] TELEGRAM_BOT_TOKEN настроен
- [ ] TELEGRAM_CHAT_ID настроен
- [ ] AlertManager email (опционально) настроен
- [ ] Все Prometheus targets UP
- [ ] Grafana dashboards загружаются
- [ ] Тестовый алерт получен
- [ ] Retention настроен под дисковое пространство
- [ ] Backup процедура протестирована
- [ ] Oncall rotation настроен
- [ ] Runbook известен команде
