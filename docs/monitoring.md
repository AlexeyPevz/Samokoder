# Мониторинг и Алертинг Samokoder

## Обзор

Samokoder использует комплексный стек мониторинга:
- **Prometheus** — сбор и хранение метрик
- **Grafana** — визуализация и дашборды
- **AlertManager** — управление алертами и уведомления
- **Exporters** — метрики PostgreSQL, Redis, Docker

## Архитектура

```
┌─────────────┐
│  Samokoder  │──────┐
│     API     │      │
└─────────────┘      │
                     │ /metrics
┌─────────────┐      │
│  Postgres   │──────┤
│  Exporter   │      │
└─────────────┘      │
                     ▼
┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│    Redis    │─▶│  Prometheus  │─▶│ AlertManager │─▶│   Telegram   │
│  Exporter   │  └──────────────┘  └──────────────┘  │    Email     │
└─────────────┘         │                             └──────────────┘
                        │
┌─────────────┐         │
│  cAdvisor   │─────────┘
│  (Docker)   │         │
└─────────────┘         ▼
                  ┌──────────────┐
                  │   Grafana    │
                  └──────────────┘
```

## Быстрый старт

### 1. Настройка окружения

```bash
# Копируйте и заполните .env
cp .env.example .env

# Обязательные переменные для алертов:
TELEGRAM_BOT_TOKEN=<получить от @BotFather>
TELEGRAM_CHAT_ID=<ваш chat_id>
```

### 2. Запуск

```bash
# Запустить весь стек
docker-compose up -d

# Проверить статус
docker-compose ps
```

### 3. Доступ к интерфейсам

| Сервис | URL | Credentials |
|--------|-----|-------------|
| Grafana | http://localhost:3000 | admin/admin (изменить!) |
| Prometheus | http://localhost:9090 | - |
| AlertManager | http://localhost:9093 | - |
| API Metrics | http://localhost:8000/metrics | - |

## Метрики

### HTTP метрики

```promql
# Request rate
rate(samokoder_http_requests_total[5m])

# Latency p95
histogram_quantile(0.95, rate(samokoder_http_request_duration_seconds_bucket[5m]))

# Error rate
rate(samokoder_http_requests_total{status=~"5.."}[5m]) / rate(samokoder_http_requests_total[5m])

# Requests in progress
samokoder_http_requests_in_progress
```

### Business метрики

```promql
# Проекты создано
rate(samokoder_projects_created_total[1h])

# LLM запросы
rate(samokoder_llm_requests_total[5m])

# LLM токены (стоимость)
rate(samokoder_llm_tokens_consumed_total[1h])

# Длительность генерации проектов
histogram_quantile(0.95, rate(samokoder_projects_generation_duration_seconds_bucket[1h]))
```

### Системные метрики

```promql
# CPU
samokoder_system_cpu_usage_percent

# Memory usage %
100 * samokoder_system_memory_usage_bytes{type="used"} / samokoder_system_memory_usage_bytes{type="total"}

# Disk usage %
100 * samokoder_system_disk_usage_bytes{type="used"} / samokoder_system_disk_usage_bytes{type="total"}
```

### Database метрики

```promql
# Query latency
histogram_quantile(0.95, rate(samokoder_db_query_duration_seconds_bucket[5m]))

# Errors
rate(samokoder_db_errors_total[5m])

# Active connections
samokoder_db_connections_active
```

## Алерты

### Critical (немедленно)

| Alert | Условие | Действие |
|-------|---------|----------|
| APIDown | API недоступен > 1 min | Telegram + Email |
| LowDiskSpace | Свободно < 10% > 5 min | Telegram + Email |

### Warning (в течение часа)

| Alert | Условие | Действие |
|-------|---------|----------|
| HighErrorRate | 5xx > 5% за 5 min | Telegram |
| HighLatency | p95 > 5s за 10 min | Telegram |
| HighLLMErrorRate | LLM errors > 10% за 10 min | Telegram |
| HighCPUUsage | CPU > 80% за 10 min | Telegram |
| HighMemoryUsage | Memory > 85% за 10 min | Telegram |

### Info (мониторим)

| Alert | Условие | Действие |
|-------|---------|----------|
| HighRateLimitHits | Rate limit > 10 req/s | Telegram |
| NoProjectsCreated | Нет проектов за 2 часа | Telegram |

## Дашборды Grafana

### Samokoder Overview

**Расположение**: Grafana → Dashboards → Samokoder Overview

**Панели**:
1. **HTTP Request Rate** — RPS по endpoint/method/status
2. **API Latency (p95)** — 95th percentile задержки
3. **Error Rate (5xx)** — процент ошибок
4. **Requests In Progress** — активные запросы
5. **LLM Request Rate** — запросы к LLM провайдерам
6. **LLM Token Consumption** — расход токенов (стоимость)
7. **CPU/Memory/Disk Gauges** — системные ресурсы
8. **API Health** — статус (up/down)

### Создание кастомных дашбордов

```bash
# 1. Создайте dashboard в Grafana UI
# 2. Export JSON (Share → Export)
# 3. Сохраните в monitoring/grafana/dashboards/
# 4. Перезапустите Grafana
docker-compose restart grafana
```

## Настройка Telegram алертов

### 1. Создание бота

```bash
# Telegram → @BotFather
/newbot
# Следуйте инструкциям
# Сохраните token
```

### 2. Получение Chat ID

```bash
# Telegram → @userinfobot
# Отправьте /start
# Скопируйте ваш ID
```

### 3. Обновите .env

```bash
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
TELEGRAM_CHAT_ID=987654321
```

### 4. Тест

```bash
# Перезапустить AlertManager
docker-compose restart alertmanager

# Проверить конфигурацию
curl http://localhost:9093/api/v2/status
```

## Настройка Email алертов

### Gmail (пример)

```bash
# .env
ALERT_EMAIL=your-email@gmail.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=<app-specific password>
```

**Создание App Password**:
1. Google Account → Security
2. 2-Step Verification → App passwords
3. Создать пароль для "Mail"
4. Использовать в SMTP_PASS

## Production настройки

### Retention

```yaml
# monitoring/prometheus/prometheus.yml
--storage.tsdb.retention.time=30d  # Хранить 30 дней
```

**Рекомендации**:
- Development: 7d
- Production: 30-90d
- Long-term: экспорт в S3/Cortex/Thanos

### Ресурсы

**Минимальные требования**:
- Prometheus: 2GB RAM, 10GB disk
- Grafana: 512MB RAM, 1GB disk
- AlertManager: 256MB RAM, 1GB disk

**Расчет disk для Prometheus**:
```
metrics/s * bytes_per_metric * retention_seconds
Пример: 1000 * 2 * (30*24*3600) ≈ 5GB
```

### Безопасность

1. **Grafana**:
```bash
# Изменить дефолтный пароль
GRAFANA_ADMIN_PASSWORD=<strong-password>
```

2. **Prometheus/AlertManager**:
```yaml
# Добавить basic auth через reverse proxy (nginx)
location /prometheus {
    auth_basic "Prometheus";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://localhost:9090;
}
```

3. **Firewall**:
```bash
# Закрыть порты, оставить только Grafana через HTTPS
ufw deny 9090  # Prometheus
ufw deny 9093  # AlertManager
ufw allow 443  # Grafana через nginx
```

## Troubleshooting

### Метрики не собираются

```bash
# Проверить targets в Prometheus
curl http://localhost:9090/api/v1/targets

# Проверить /metrics endpoint
curl http://localhost:8000/metrics

# Логи Prometheus
docker logs samokoder-prometheus
```

### Алерты не приходят

```bash
# Проверить AlertManager status
curl http://localhost:9093/api/v2/status

# Проверить silences/inhibitions
curl http://localhost:9093/api/v2/silences
curl http://localhost:9093/api/v2/alerts

# Тестовый алерт
curl -H "Content-Type: application/json" -d '[{"labels":{"alertname":"TestAlert"}}]' http://localhost:9093/api/v1/alerts

# Логи
docker logs samokoder-alertmanager
```

### Grafana не показывает данные

```bash
# Проверить datasource
Grafana → Configuration → Data Sources → Prometheus → Test

# Проверить query в Explore
Grafana → Explore → Query: up

# Логи
docker logs samokoder-grafana
```

## Метрики в коде

### Пример: трекинг LLM запросов

```python
from api.middleware.metrics import (
    llm_requests_total,
    llm_request_duration_seconds,
    llm_tokens_consumed_total,
    llm_request_errors_total
)

async def call_llm(provider: str, model: str, prompt: str):
    start_time = time.time()
    
    try:
        response = await llm_client.generate(provider, model, prompt)
        
        # Успех
        llm_requests_total.labels(
            provider=provider,
            model=model,
            agent="code_generator"
        ).inc()
        
        # Токены
        llm_tokens_consumed_total.labels(
            provider=provider,
            model=model,
            token_type="prompt"
        ).inc(response.prompt_tokens)
        
        llm_tokens_consumed_total.labels(
            provider=provider,
            model=model,
            token_type="completion"
        ).inc(response.completion_tokens)
        
        return response
        
    except Exception as e:
        # Ошибка
        llm_request_errors_total.labels(
            provider=provider,
            error_type=type(e).__name__
        ).inc()
        raise
        
    finally:
        # Latency
        duration = time.time() - start_time
        llm_request_duration_seconds.labels(
            provider=provider,
            model=model
        ).observe(duration)
```

### Пример: трекинг бизнес-событий

```python
from api.middleware.metrics import (
    projects_created_total,
    projects_generation_duration_seconds
)

async def create_project(user: User, description: str):
    start_time = time.time()
    
    try:
        project = await generate_project(description)
        
        # Счетчик проектов
        projects_created_total.labels(
            user_tier=user.tier  # free/pro/enterprise
        ).inc()
        
        return project
        
    finally:
        # Длительность генерации
        duration = time.time() - start_time
        complexity = estimate_complexity(description)
        
        projects_generation_duration_seconds.labels(
            complexity=complexity  # simple/medium/complex
        ).observe(duration)
```

## Расширенные сценарии

### Федерация Prometheus (multi-region)

```yaml
# Central Prometheus
scrape_configs:
  - job_name: 'federate'
    scrape_interval: 15s
    honor_labels: true
    metrics_path: '/federate'
    params:
      'match[]':
        - '{job="samokoder-api"}'
    static_configs:
      - targets:
          - 'prometheus-eu:9090'
          - 'prometheus-us:9090'
```

### Long-term storage (Thanos/Cortex)

Для хранения > 90 дней рекомендуется:
- **Thanos** — S3/GCS backend
- **Cortex** — managed service
- **VictoriaMetrics** — on-prem альтернатива

### SLO/SLI мониторинг

```promql
# SLI: Availability (99.9%)
sum(rate(samokoder_http_requests_total{status!~"5.."}[30d]))
/
sum(rate(samokoder_http_requests_total[30d]))

# SLI: Latency (p95 < 500ms)
histogram_quantile(0.95, rate(samokoder_http_request_duration_seconds_bucket[30d])) < 0.5

# Error budget
1 - 0.999  # 0.1% downtime = ~43 min/month
```

## Полезные ссылки

- [Prometheus Query Examples](https://prometheus.io/docs/prometheus/latest/querying/examples/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)
- [AlertManager Configuration](https://prometheus.io/docs/alerting/latest/configuration/)
- [Best Practices: Instrumentation](https://prometheus.io/docs/practices/instrumentation/)
- [PromQL Cheat Sheet](https://promlabs.com/promql-cheat-sheet/)
