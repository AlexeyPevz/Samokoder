# Rollback Procedure для Samokoder

**Дата создания:** 2025-10-06  
**Версия:** 1.0  
**Автор:** DevOps/SRE Team

---

## Обзор

Процедуры отката (rollback) для быстрого восстановления работоспособности системы после неудачного деплоя.

**Целевое время отката (Rollback Time Objective, RTO):** < 5 минут

---

## Сценарий 1: Откат API (Docker образы)

### Признаки необходимости отката

- Резкий рост ошибок 5xx (> 5% error rate)
- P95 latency > 5s
- Health check падает
- Critical alerts firing
- Broken functionality reported by users

### Процедура автоматического отката

#### Шаг 1: Идентификация предыдущей версии (1 минута)

```bash
# Посмотреть текущую версию
docker ps --filter name=samokoder-api --format "table {{.Image}}\t{{.Status}}"

# Посмотреть доступные версии в registry
docker images | grep samokoder-api | head -5

# Или из логов deployment
git log --oneline -10
```

#### Шаг 2: Быстрый откат через docker-compose (2 минуты)

```bash
# Вариант А: Откат к предыдущему тегу
export APP_VERSION="<previous-version>"  # например: v1.2.3

# Быстрый откат API
docker-compose pull api
docker-compose up -d --no-deps api

# Проверка
curl http://localhost:8000/health
```

#### Шаг 3: Откат через скрипт (РЕКОМЕНДУЕТСЯ)

```bash
# Использовать автоматический rollback скрипт
cd /opt/samokoder/ops/scripts
./rollback.sh --service=api --to-version=<previous-version>

# Или откат к последней working версии
./rollback.sh --service=api --auto
```

#### Шаг 4: Верификация (1 минута)

```bash
# Smoke tests
/opt/samokoder/ops/scripts/smoke-test.sh

# Проверка метрик
curl -s http://localhost:8000/metrics | grep samokoder_http_requests_total

# Проверка error rate
curl -s 'http://localhost:9090/api/v1/query?query=rate(samokoder_http_requests_total{status=~"5.."}[5m])' | jq
```

#### Шаг 5: Мониторинг (5 минут)

```bash
# Наблюдать метрики
watch -n 5 'curl -s http://localhost:9090/api/v1/query?query=up{job="samokoder-api"}'

# Проверить алерты
curl http://localhost:9093/api/v2/alerts | jq '.[] | select(.status.state=="active")'
```

---

## Сценарий 2: Откат миграций базы данных

### ⚠️ ВНИМАНИЕ: Откат миграций может привести к потере данных!

### Процедура

#### Шаг 1: Создать backup перед откатом (ОБЯЗАТЕЛЬНО)

```bash
cd /opt/samokoder/ops/scripts
./backup.sh

# Верифицировать backup
LATEST_BACKUP=$(ls -t /var/backups/samokoder/postgres/samokoder_*.sql.gz | head -1)
gunzip -t $LATEST_BACKUP && echo "✅ Backup valid" || echo "❌ Backup corrupted!"
```

#### Шаг 2: Остановить зависимые сервисы

```bash
# Остановить API и Worker (предотвратить запросы к БД)
docker-compose stop api worker

# Установить maintenance mode (503 для всех запросов)
# Через Traefik или nginx
```

#### Шаг 3: Откатить миграцию Alembic

```bash
# Посмотреть текущую версию миграции
docker exec samokoder-api alembic current

# Посмотреть историю
docker exec samokoder-api alembic history

# Откатить на 1 версию назад
docker exec samokoder-api alembic downgrade -1

# Или к конкретной ревизии
docker exec samokoder-api alembic downgrade <revision_id>

# Проверить успешность
docker exec samokoder-api alembic current
```

#### Шаг 4: Откатить код API

```bash
# Откатить API к версии, совместимой с миграцией
export APP_VERSION="<compatible-version>"
docker-compose pull api worker
docker-compose up -d api worker
```

#### Шаг 5: Проверка целостности данных

```bash
# Подключиться к БД
docker exec -it samokoder-db psql -U user -d samokoder

-- Проверить критичные таблицы
SELECT 'users' as table, COUNT(*) FROM users
UNION ALL
SELECT 'projects', COUNT(*) FROM projects
UNION ALL
SELECT 'files', COUNT(*) FROM files;

-- Проверить constraints
SELECT conname, conrelid::regclass, confrelid::regclass
FROM pg_constraint
WHERE contype = 'f';
```

#### Шаг 6: Smoke testing

```bash
cd /opt/samokoder/ops/scripts
./smoke-test.sh --verbose
```

---

## Сценарий 3: Полный откат deployment (код + БД + конфигурация)

### Когда использовать
- Множественные проблемы после deployment
- Неизвестная root cause
- Критичный production incident

### Процедура "Nuclear Option"

#### Шаг 1: Объявить инцидент

```bash
# Уведомить команду
# Slack/Telegram: @channel Production incident - rolling back deployment
```

#### Шаг 2: Snapshot текущего состояния (для post-mortem)

```bash
# Создать "crisis backup"
./ops/scripts/backup.sh
mv /var/backups/samokoder/postgres/samokoder_*.sql.gz \
   /var/backups/samokoder/postgres/incident_$(date +%Y%m%d_%H%M%S).sql.gz

# Собрать логи
docker-compose logs --since 30m > /tmp/incident-logs-$(date +%Y%m%d_%H%M%S).log
```

#### Шаг 3: Откат к последнему известному working state

```bash
# Найти последний working commit
git log --oneline -20
# Или из tag
git tag -l | tail -5

# Checkout предыдущий tag
git checkout v1.2.3  # или конкретный commit

# Пересобрать и задеплоить
./deploy.sh --force-rebuild

# Или через docker images
export APP_VERSION=v1.2.3
docker-compose pull
docker-compose up -d --force-recreate
```

#### Шаг 4: Восстановление данных (если нужно)

```bash
# Если миграция повредила данные
cd /opt/samokoder/ops/scripts
./restore.sh /var/backups/samokoder/postgres/pre-deploy-backup.sql.gz

# Применить миграции для откатываемой версии
docker exec samokoder-api alembic upgrade head
```

---

## Сценарий 4: Откат конфигурации (Environment Variables)

### Процедура

```bash
# 1. Найти предыдущий .env (из git или backup)
git show HEAD~1:.env.prod > .env.prod.previous

# 2. Сравнить различия
diff .env.prod .env.prod.previous

# 3. Восстановить нужные переменные
cp .env.prod.previous .env.prod

# 4. Перезапустить сервисы для применения
docker-compose up -d --force-recreate api worker

# 5. Проверить
docker-compose exec api env | grep -E "(SECRET_KEY|DATABASE_URL|REDIS)"
```

---

## Автоматизированный скрипт отката

Создан скрипт `/opt/samokoder/ops/scripts/rollback.sh` для автоматизации:

```bash
# Примеры использования:

# 1. Откатить API к конкретной версии
./rollback.sh --service=api --to-version=v1.2.3

# 2. Автоматический откат к последней working версии
./rollback.sh --service=api --auto

# 3. Полный rollback (API + Worker + Frontend)
./rollback.sh --full --to-version=v1.2.3

# 4. Rollback с восстановлением БД
./rollback.sh --full --to-version=v1.2.3 --restore-db

# 5. Dry-run (посмотреть что будет сделано)
./rollback.sh --service=api --to-version=v1.2.3 --dry-run
```

---

## Validation Checklist после отката

- [ ] Health check проходит: `curl http://localhost:8000/health`
- [ ] Error rate < 1%: проверить в Grafana
- [ ] P95 latency < 2s: проверить в Grafana
- [ ] Критичные алерты resolved
- [ ] Smoke tests пройдены: `./smoke-test.sh`
- [ ] Database queries работают
- [ ] User-facing функциональность работает
- [ ] Мониторинг показывает нормальные метрики

---

## Предотвращение необходимости отката

### Pre-deployment validation

1. **Staging environment тестирование**
   ```bash
   # Задеплоить на staging первым
   ./deploy.sh --env=staging
   
   # Прогнать integration tests
   ./ops/scripts/integration-test.sh --env=staging
   ```

2. **Database migration validation**
   ```bash
   # Проверить миграцию на копии production БД
   # До применения в production
   ```

3. **Canary deployment** (TODO: implement)
   ```bash
   # Задеплоить на 10% трафика
   # Мониторить метрики
   # Если OK → 100%, если не OK → rollback
   ```

4. **Feature flags**
   ```bash
   # Использовать feature flags для новой функциональности
   # Можно отключить проблемную фичу без rollback
   ```

---

## Post-Rollback Actions

### Немедленно (< 1 час)

- [ ] Создать incident report
- [ ] Уведомить stakeholders о восстановлении
- [ ] Задокументировать root cause (preliminary)
- [ ] Создать ticket для fix

### В течение 24 часов

- [ ] Провести post-mortem meeting
- [ ] Обновить runbook на основе опыта
- [ ] Создать превентивные меры
- [ ] Обновить monitoring/alerting (если нужно)

### В течение недели

- [ ] Исправить root cause
- [ ] Добавить тесты для предотвращения regression
- [ ] Обновить deployment процесс
- [ ] Поделиться lessons learned с командой

---

## Контакты для эскалации

| Тип инцидента | Контакт | SLA |
|---------------|---------|-----|
| API rollback | DevOps on-call | 15 min |
| DB rollback | Database team + DevOps lead | 30 min |
| Full rollback | Incident Commander + CTO | Immediate |

**On-call rotation:** https://samokoder.pagerduty.com

---

## Метрики для принятия решения об откате

| Метрика | Порог для рассмотрения отката | Порог для немедленного отката |
|---------|------------------------------|-------------------------------|
| Error rate (5xx) | > 3% | > 10% |
| P95 latency | > 3s | > 10s |
| Health check failures | > 2 за 5 минут | > 5 за 1 минуту |
| Database errors | > 10/min | > 100/min |
| User complaints | > 3 | > 10 |
| Critical alerts | 1 firing | 3+ firing |

---

## Lessons Learned (обновлять после каждого отката)

### 2025-10-06 - Initial version
- Создан первый rollback runbook
- Требуется автоматизация для ускорения процесса
- Необходим staging environment для validation
