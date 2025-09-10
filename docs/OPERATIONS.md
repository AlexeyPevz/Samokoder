# 🔧 Операционные инструкции - Самокодер v1.0.0

> **Руководство по эксплуатации и администрированию**  
> Для DevOps инженеров, системных администраторов и SRE

## 📋 Содержание

- [Мониторинг и алерты](#-мониторинг-и-алерты)
- [Управление сервисами](#-управление-сервисами)
- [Резервное копирование](#-резервное-копирование)
- [Обновления и миграции](#-обновления-и-миграции)
- [Устранение неполадок](#-устранение-неполадок)
- [Масштабирование](#-масштабирование)
- [Безопасность](#-безопасность)
- [Производительность](#-производительность)

## 📊 Мониторинг и алерты

### 🎯 Golden Signals

#### Latency (Задержка)
```bash
# Проверка задержки API
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/health

# Создайте curl-format.txt
cat > curl-format.txt << 'EOF'
     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n
EOF

# Пороги:
# - P50: < 100ms
# - P95: < 500ms
# - P99: < 1000ms
```

#### Traffic (Трафик)
```bash
# Мониторинг запросов в секунду
watch -n 1 'curl -s http://localhost:8000/metrics | grep http_requests_total'

# Пороги:
# - Нормальная нагрузка: 100-500 RPS
# - Высокая нагрузка: 500-1000 RPS
# - Критическая нагрузка: > 1000 RPS
```

#### Errors (Ошибки)
```bash
# Мониторинг ошибок
curl -s http://localhost:8000/metrics | grep http_requests_total | grep "status=\"5"

# Пороги:
# - Нормальный уровень: < 1%
# - Предупреждение: 1-5%
# - Критический уровень: > 5%
```

#### Saturation (Насыщение)
```bash
# Мониторинг ресурсов
# CPU
top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1

# Memory
free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }'

# Disk
df -h | awk '$NF=="/"{printf "%s", $5}'

# Пороги:
# - CPU: < 70%
# - Memory: < 80%
# - Disk: < 85%
```

### 📈 Prometheus метрики

#### Настройка Prometheus
```yaml
# monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'samokoder'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']
```

#### Запуск Prometheus
```bash
# Docker
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/monitoring/prometheus:/etc/prometheus \
  prom/prometheus

# Или локально
prometheus --config.file=monitoring/prometheus/prometheus.yml
```

### 🚨 Алерты

#### Настройка Alertmanager
```yaml
# monitoring/alertmanager/alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@samokoder.com'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://localhost:5001/'
```

#### Правила алертов
```yaml
# monitoring/prometheus/rules/alerts.yml
groups:
- name: samokoder
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High latency detected"
      description: "95th percentile latency is {{ $value }}s"

  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage"
      description: "CPU usage is {{ $value }}%"
```

## 🔧 Управление сервисами

### 🚀 Запуск сервисов

#### Development режим
```bash
# Автоматический запуск
./scripts/start_dev.sh

# Или ручной запуск
# Терминал 1 - Backend
python run_server.py

# Терминал 2 - Frontend
cd frontend && npm run dev

# Терминал 3 - Redis (если нужен)
redis-server
```

#### Production режим
```bash
# Docker Compose
docker-compose -f docker-compose.prod.yml up -d

# Или systemd сервисы
sudo systemctl start samokoder-backend
sudo systemctl start samokoder-frontend
sudo systemctl start samokoder-nginx
```

### 🛑 Остановка сервисов

```bash
# Graceful shutdown
docker-compose down

# Или systemd
sudo systemctl stop samokoder-backend
sudo systemctl stop samokoder-frontend

# Принудительная остановка
pkill -f "python run_server.py"
pkill -f "npm run dev"
```

### 🔄 Перезапуск сервисов

```bash
# Docker Compose
docker-compose restart

# Или systemd
sudo systemctl restart samokoder-backend
sudo systemctl restart samokoder-frontend

# Или по отдельности
sudo systemctl reload samokoder-nginx
```

### 📊 Проверка статуса

```bash
# Проверка всех сервисов
./scripts/health_check.sh

# Автоматическая проверка воспроизводимости
python scripts/test_reproducibility.py

# Или по отдельности
curl http://localhost:8000/health
curl http://localhost:5173
curl http://localhost:9090/metrics
```

## 💾 Резервное копирование

### 🗄️ База данных

#### Supabase
```bash
# Создание бэкапа через Supabase CLI
supabase db dump --file backup_$(date +%Y%m%d_%H%M%S).sql

# Восстановление
supabase db reset --file backup_20250910_120000.sql
```

#### PostgreSQL
```bash
# Создание бэкапа
pg_dump -h localhost -U samokoder -d samokoder > backup_$(date +%Y%m%d_%H%M%S).sql

# Сжатый бэкап
pg_dump -h localhost -U samokoder -d samokoder | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Восстановление
psql -h localhost -U samokoder -d samokoder < backup_20250910_120000.sql

# Восстановление из сжатого
gunzip -c backup_20250910_120000.sql.gz | psql -h localhost -U samokoder -d samokoder
```

#### Автоматическое резервное копирование
```bash
# Создайте скрипт бэкапа
cat > scripts/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/samokoder"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/samokoder_$DATE.sql"

mkdir -p $BACKUP_DIR

# Создание бэкапа
pg_dump -h localhost -U samokoder -d samokoder > $BACKUP_FILE

# Сжатие
gzip $BACKUP_FILE

# Удаление старых бэкапов (старше 30 дней)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

echo "Backup created: $BACKUP_FILE.gz"
EOF

chmod +x scripts/backup.sh

# Добавьте в crontab
echo "0 2 * * * /path/to/samokoder/scripts/backup.sh" | crontab -
```

### 📁 Файлы приложения

```bash
# Бэкап файлов
tar -czf app_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
  exports/ \
  workspaces/ \
  logs/ \
  .env

# Восстановление
tar -xzf app_backup_20250910_120000.tar.gz
```

### 🔐 Секреты и конфигурация

```bash
# Бэкап конфигурации (без секретов)
cp .env .env.backup
cp -r config/ config_backup/

# Восстановление
cp .env.backup .env
cp -r config_backup/ config/
```

## 🔄 Обновления и миграции

### 📦 Обновление приложения

#### Подготовка к обновлению
```bash
# 1. Создайте бэкап
./scripts/backup.sh

# 2. Проверьте текущую версию
git describe --tags

# 3. Проверьте изменения
git log --oneline HEAD..origin/main
```

#### Обновление кода
```bash
# 1. Остановите сервисы
docker-compose down

# 2. Обновите код
git fetch origin
git checkout main
git pull origin main

# 3. Обновите зависимости
pip install -r requirements.txt
cd frontend && npm install && cd ..

# 4. Выполните миграции
python -m alembic upgrade head

# 5. Запустите тесты
make test

# 6. Запустите сервисы
docker-compose up -d
```

#### Откат обновления
```bash
# 1. Остановите сервисы
docker-compose down

# 2. Откатите код
git checkout <previous-tag>
git pull origin <previous-tag>

# 3. Откатите миграции (если нужно)
python -m alembic downgrade -1

# 4. Восстановите бэкап БД
psql -h localhost -U samokoder -d samokoder < backup_20250910_120000.sql

# 5. Запустите сервисы
docker-compose up -d
```

### 🗄️ Миграции базы данных

#### Создание миграции
```bash
# Создайте новую миграцию
python -m alembic revision --autogenerate -m "Add new table"

# Отредактируйте файл миграции
# Файл будет в database/migrations/versions/
```

#### Применение миграций
```bash
# Просмотр текущей версии
python -m alembic current

# Просмотр истории
python -m alembic history

# Применение миграций
python -m alembic upgrade head

# Применение конкретной миграции
python -m alembic upgrade <revision_id>
```

#### Откат миграций
```bash
# Откат на одну миграцию
python -m alembic downgrade -1

# Откат до конкретной версии
python -m alembic downgrade <revision_id>

# Откат всех миграций
python -m alembic downgrade base
```

## ✅ Проверка воспроизводимости

### 🧪 Тест установки "с нуля"

Для проверки, что приложение можно установить и запустить с нуля:

```bash
# Запустите автоматическую проверку
python scripts/test_reproducibility.py

# Или используйте Makefile
make health
```

### 🔍 Ручная проверка

```bash
# 1. Проверьте файлы
ls -la .env.example README.md requirements.txt

# 2. Проверьте зависимости
python -c "import fastapi, uvicorn, supabase"

# 3. Проверьте конфигурацию
python -c "from config.settings import settings; print('Config OK')"

# 4. Проверьте сервер
curl http://localhost:8000/health

# 5. Проверьте API документацию
curl http://localhost:8000/docs
```

## 🐛 Устранение неполадок

### 🔍 Диагностика проблем

#### Проверка логов
```bash
# Логи приложения
tail -f logs/app.log

# Логи Docker
docker-compose logs -f

# Логи systemd
journalctl -u samokoder-backend -f
journalctl -u samokoder-frontend -f
```

#### Проверка ресурсов
```bash
# CPU и память
htop

# Диск
df -h
du -sh /var/lib/docker

# Сеть
netstat -tulpn | grep :8000
netstat -tulpn | grep :5173
```

#### Проверка подключений
```bash
# База данных
psql -h localhost -U samokoder -d samokoder -c "SELECT 1;"

# Redis
redis-cli ping

# API
curl -v http://localhost:8000/health
```

### 🚨 Критические проблемы

#### Приложение не запускается
```bash
# 1. Проверьте логи
docker-compose logs

# 2. Проверьте конфигурацию
python -c "from config.settings import settings; print('Config OK')"

# 3. Проверьте зависимости
pip check

# 4. Проверьте порты
lsof -i :8000
lsof -i :5173
```

#### База данных недоступна
```bash
# 1. Проверьте статус PostgreSQL
sudo systemctl status postgresql

# 2. Проверьте подключение
psql -h localhost -U samokoder -d samokoder

# 3. Проверьте логи PostgreSQL
sudo journalctl -u postgresql -f

# 4. Проверьте место на диске
df -h
```

#### Высокая нагрузка
```bash
# 1. Проверьте метрики
curl http://localhost:9090/metrics | grep http_requests_total

# 2. Проверьте процессы
ps aux | grep python

# 3. Проверьте память
free -h

# 4. Масштабируйте приложение
docker-compose up -d --scale backend=3
```

### 🔧 Восстановление после сбоев

#### Восстановление базы данных
```bash
# 1. Остановите приложение
docker-compose down

# 2. Восстановите бэкап
psql -h localhost -U samokoder -d samokoder < backup_20250910_120000.sql

# 3. Проверьте целостность
psql -h localhost -U samokoder -d samokoder -c "VACUUM ANALYZE;"

# 4. Запустите приложение
docker-compose up -d
```

#### Восстановление файлов
```bash
# 1. Остановите приложение
docker-compose down

# 2. Восстановите файлы
tar -xzf app_backup_20250910_120000.tar.gz

# 3. Проверьте права доступа
chown -R samokoder:samokoder exports/ workspaces/

# 4. Запустите приложение
docker-compose up -d
```

## 📈 Масштабирование

### 🔄 Горизонтальное масштабирование

#### Load Balancer (Nginx)
```nginx
# /etc/nginx/sites-available/samokoder
upstream backend {
    server 127.0.0.1:8000;
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
}

upstream frontend {
    server 127.0.0.1:5173;
    server 127.0.0.1:5174;
}

server {
    listen 80;
    server_name samokoder.com;

    location /api/ {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### Docker Swarm
```yaml
# docker-stack.yml
version: '3.8'
services:
  backend:
    image: samokoder/backend:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
    environment:
      - DATABASE_URL=${DATABASE_URL}
    networks:
      - samokoder

  frontend:
    image: samokoder/frontend:latest
    deploy:
      replicas: 2
    networks:
      - samokoder

networks:
  samokoder:
    driver: overlay
```

### 📊 Вертикальное масштабирование

#### Увеличение ресурсов
```bash
# Увеличение памяти для Docker
docker run -m 2g samokoder/backend

# Или в docker-compose.yml
services:
  backend:
    image: samokoder/backend:latest
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2.0'
```

## 🔐 Безопасность

### 🔑 Управление секретами

#### Ротация ключей
```bash
# Создайте скрипт ротации
cat > scripts/rotate_keys.sh << 'EOF'
#!/bin/bash
# Генерация новых ключей
NEW_JWT_SECRET=$(openssl rand -base64 32)
NEW_API_KEY=$(openssl rand -base64 32)

# Обновление .env
sed -i "s/JWT_SECRET=.*/JWT_SECRET=$NEW_JWT_SECRET/" .env
sed -i "s/API_ENCRYPTION_KEY=.*/API_ENCRYPTION_KEY=$NEW_API_KEY/" .env

# Перезапуск сервисов
docker-compose restart backend

echo "Keys rotated successfully"
EOF

chmod +x scripts/rotate_keys.sh
```

#### Мониторинг безопасности
```bash
# Проверка уязвимостей
pip-audit

# Проверка зависимостей
safety check

# Сканирование Docker образов
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image samokoder/backend:latest
```

### 🛡️ Firewall и сеть

```bash
# Настройка UFW
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw deny 8000/tcp   # Backend (только локально)
sudo ufw deny 5173/tcp   # Frontend (только локально)
sudo ufw enable
```

## ⚡ Производительность

### 📊 Оптимизация базы данных

#### Индексы
```sql
-- Создание индексов для производительности
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_projects_user_id ON projects(user_id);
CREATE INDEX CONCURRENTLY idx_projects_created_at ON projects(created_at);
CREATE INDEX CONCURRENTLY idx_chat_messages_project_id ON chat_messages(project_id);
```

#### Анализ запросов
```sql
-- Включение логирования медленных запросов
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_reload_conf();

-- Анализ статистики
SELECT * FROM pg_stat_user_tables;
SELECT * FROM pg_stat_user_indexes;
```

### 🚀 Оптимизация приложения

#### Кэширование
```python
# Настройка Redis кэширования
import redis
from functools import wraps

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def cache_result(expiration=300):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
            result = func(*args, **kwargs)
            redis_client.setex(cache_key, expiration, json.dumps(result))
            return result
        return wrapper
    return decorator
```

#### Connection Pooling
```python
# Настройка пула соединений
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    pool_recycle=3600
)
```

---

## 🎯 Чек-лист операций

### ✅ Ежедневные задачи
- [ ] Проверка статуса сервисов
- [ ] Мониторинг метрик
- [ ] Проверка логов на ошибки
- [ ] Проверка места на диске
- [ ] Проверка резервных копий

### ✅ Еженедельные задачи
- [ ] Анализ производительности
- [ ] Обновление зависимостей
- [ ] Проверка безопасности
- [ ] Тестирование восстановления
- [ ] Ротация логов

### ✅ Ежемесячные задачи
- [ ] Ротация ключей
- [ ] Обновление системы
- [ ] Анализ использования ресурсов
- [ ] Планирование масштабирования
- [ ] Аудит безопасности

---

**Создано с ❤️ командой Самокодер**  
**© 2025 Samokoder. Все права защищены.**